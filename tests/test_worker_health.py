import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app import remote, worker as worker_module
from app.config import Settings
from app.db import Store
from app.worker import JobWorker


def make_worker(tmp_path, enabled=True, capacity=1):
    settings = Settings(secret="worker-health-test-secret-" * 3, data_dir=tmp_path,
                        enable_worker=enabled, max_concurrent_jobs=capacity)
    store = Store(settings.database)
    store.add_user("health-customer", "unused-hash")
    return JobWorker(store, settings)


def add_job(worker, task_id="health_1", ip="8.8.8.8"):
    password = worker.box.encrypt(b"health-ssh-password").decode()
    return worker.store.create_task(dict(
        id=task_id, user_id=1, kind="install", server_ip=ip, ssh_port=22,
        ssh_username="root", domain="panel.example.com", version="2.9.4",
        panel_port=443, panel_path="/health_test_path/", source_version=None,
        overwrite_existing=False, reset_two_factor=False, encrypted_password=password,
        upload_path=None, validation=None,
    ))


async def until(predicate, timeout=2):
    async def poll():
        while not predicate():
            await asyncio.sleep(0.005)
    await asyncio.wait_for(poll(), timeout)


def test_disabled_and_not_started_worker_are_not_available(tmp_path):
    disabled = make_worker(tmp_path / "disabled", enabled=False)
    assert disabled.runtime_status() == {
        "enabled": False, "available": False, "state": "disabled",
        "message": "任务执行器未启用，请管理员开启后再提交任务。", "active_jobs": 0, "capacity": 0,
    }
    waiting = make_worker(tmp_path / "waiting")
    assert waiting.runtime_status()["state"] == "starting"
    assert waiting.runtime_status()["available"] is False


@pytest.mark.parametrize("invalid_module", [None, SimpleNamespace(run_remote_job=None, RemoteOptions=object)])
def test_startup_validates_remote_import_before_consumers(tmp_path, monkeypatch, invalid_module):
    worker = make_worker(tmp_path)
    claim = Mock()
    monkeypatch.setattr(worker.store, "claim", claim)
    def load(name):
        if invalid_module is None:
            raise ImportError("simulated missing dependency")
        return invalid_module
    monkeypatch.setattr(worker_module.importlib, "import_module", load)
    async def run():
        with pytest.raises((ImportError, RuntimeError)):
            await worker.start()
        assert worker.runtime_status()["state"] == "failed"
        assert worker.runtime_status()["available"] is False
        assert worker.lock_file is None
        assert worker.jobs == []
    asyncio.run(run())
    claim.assert_not_called()


def test_startup_failure_after_lock_releases_it_for_next_process(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    second = JobWorker(worker.store, worker.settings)
    real_interrupt = worker.store.interrupt_running
    monkeypatch.setattr(worker.store, "interrupt_running", Mock(side_effect=OSError("database locked")))
    async def run():
        with pytest.raises(OSError):
            await worker.start()
        assert worker.lock_file is None
        monkeypatch.setattr(worker.store, "interrupt_running", real_interrupt)
        await second.start()
        try:
            assert second.runtime_status()["available"]
        finally:
            await second.stop()
    asyncio.run(run())


def test_health_tracks_actual_live_consumers_and_shutdown_lock(tmp_path):
    worker = make_worker(tmp_path, capacity=2)
    async def run():
        await worker.start()
        try:
            assert worker.runtime_status()["state"] == "running"
            assert worker.runtime_status()["capacity"] == 2
            worker._consumers[0].cancel()
            await asyncio.gather(worker._consumers[0], return_exceptions=True)
            assert worker.runtime_status()["state"] == "degraded"
            assert worker.runtime_status()["capacity"] == 1
            assert worker.runtime_status()["available"]
            worker._consumers[1].cancel()
            await asyncio.gather(worker._consumers[1], return_exceptions=True)
            assert worker.runtime_status()["state"] == "failed"
            assert worker.runtime_status()["available"] is False
        finally:
            await worker.stop()
        assert worker.runtime_status()["state"] == "stopped"
        assert worker.lock_file is None
        # A fresh owner can acquire the same directory after graceful shutdown.
        replacement = JobWorker(worker.store, worker.settings)
        await replacement.start()
        await replacement.stop()
    asyncio.run(run())


def test_task_claim_is_immediate_and_heartbeat_preserves_business_stage(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    task = add_job(worker)
    monkeypatch.setattr(worker_module, "HEARTBEAT_SECONDS", 0.02)
    monkeypatch.setattr(worker_module, "QUEUE_POLL_SECONDS", 0.01)
    async def run():
        connected, change_stage, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def fake_run(job, password, upload, emit, options):
            assert password == "health-ssh-password"
            await emit("preflight", "health-ssh-password password=hidden-secret")
            connected.set()
            await change_stage.wait()
            await emit("reboot", "正在安排服务器重启。")
            await finish.wait()
            return {"url": "https://panel.example.com/health_test_path/"}
        monkeypatch.setattr(remote, "run_remote_job", fake_run)
        await worker.start()
        try:
            await asyncio.wait_for(connected.wait(), 0.5)
            assert worker.runtime_status()["active_jobs"] == 1
            assert worker.store.task(task["id"])["status"] == "running"
            assert any(event["stage"] == "starting" for event in worker.store.events(task["id"]))
            await until(lambda: any("仍在执行" in event["message"] for event in worker.store.events(task["id"])))
            assert worker.store.task(task["id"])["stage"] == "preflight"
            change_stage.set()
            await until(lambda: any(event["stage"] == "reboot" and "确认调度结果后即返回" in event["message"]
                                    for event in worker.store.events(task["id"])))
            assert worker.store.task(task["id"])["stage"] == "reboot"
            finish.set()
            await until(lambda: worker.store.task(task["id"])["status"] == "succeeded")
            saved = worker.store.events(task["id"])
            count = len(saved)
            await asyncio.sleep(0.06)
            assert len(worker.store.events(task["id"])) == count
            assert worker.store.task(task["id"])["stage"] == "completed"
            assert worker.runtime_status()["active_jobs"] == 0
            assert not any(task.get_name().startswith("job-progress-") for task in asyncio.all_tasks())
            assert all("health-ssh-password" not in event["message"] and "hidden-secret" not in event["message"] for event in saved)
            assert all("5 分钟" not in event["message"] and "超过后尝试回滚" not in event["message"] for event in saved)
        finally:
            await worker.stop()
    asyncio.run(run())


@pytest.mark.parametrize("scheduled", [True, False])
def test_migration_finishes_with_address_and_honest_reboot_status(tmp_path, monkeypatch, scheduled):
    worker = make_worker(tmp_path)
    task = add_job(worker)
    with worker.store.connect() as db:
        db.execute("UPDATE tasks SET kind='migrate' WHERE id=?", (task["id"],))
    async def fake_run(job, password, upload, emit, options):
        assert job["kind"] == "migrate"
        return {
            "url": "https://panel.example.com:8443/original/", "credentials_preserved": True,
            "panel_access_verified": True, "reboot_scheduled": scheduled, "reboot_verified": False,
        }
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        try:
            await until(lambda: worker.store.task(task["id"])["status"] == "succeeded")
            saved = worker.store.task(task["id"])
            assert saved["result"]["url"] == "https://panel.example.com:8443/original/"
            assert saved["result"]["reboot_scheduled"] is scheduled
            assert saved["result"]["reboot_verified"] is False
            assert saved["encrypted_password"] is None
            completion = [event["message"] for event in worker.store.events(task["id"]) if event["stage"] == "completed"]
            assert len(completion) == 1 and "面板地址已返回" in completion[0]
            assert ("已安排服务器重启" if scheduled else "手动重启") in completion[0]
            assert "重启后已通过" not in completion[0]
            assert any("重启前" in warning for warning in saved["result"]["warnings"])
        finally:
            await worker.stop()
    asyncio.run(run())


def test_claim_error_retries_without_killing_consumer_or_leaking_error(tmp_path, monkeypatch, caplog):
    worker = make_worker(tmp_path)
    add_job(worker)
    real_claim = worker.store.claim
    tries = 0
    def flaky_claim():
        nonlocal tries
        tries += 1
        if tries == 1:
            raise RuntimeError("password=private-claim-diagnostic")
        return real_claim()
    monkeypatch.setattr(worker.store, "claim", flaky_claim)
    monkeypatch.setattr(worker_module, "QUEUE_RETRY_SECONDS", 0.02)
    async def fake_run(*args, **kwargs):
        return {"url": "https://panel.example.com/"}
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        try:
            assert worker.runtime_status()["state"] == "degraded"
            assert worker.runtime_status()["available"]
            await until(lambda: worker.store.task("health_1")["status"] == "succeeded")
            assert worker.runtime_status()["state"] == "running"
        finally:
            await worker.stop()
    asyncio.run(run())
    assert "private-claim-diagnostic" not in caplog.text


def test_one_failed_job_does_not_strand_the_following_queue(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    add_job(worker, "first", "8.8.8.8")
    add_job(worker, "second", "1.1.1.1")
    async def fake_run(job, password, *args, **kwargs):
        if job["id"] == "first":
            raise RuntimeError("failed with " + password)
        return {"url": "https://panel.example.com/"}
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        try:
            await until(lambda: worker.store.task("second")["status"] == "succeeded")
            assert worker.store.task("first")["status"] == "failed"
            assert "health-ssh-password" not in worker.store.task("first")["error"]
            assert worker.runtime_status()["available"]
        finally:
            await worker.stop()
    asyncio.run(run())


def test_final_event_write_failure_cannot_downgrade_a_successful_result(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    add_job(worker)
    original = worker.store.event
    def event(task_id, stage, message):
        if stage == "completed":
            raise OSError("simulated log write failure")
        original(task_id, stage, message)
    monkeypatch.setattr(worker.store, "event", event)
    async def fake_run(*args, **kwargs):
        return {"url": "https://panel.example.com/"}
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        try:
            await until(lambda: worker.store.task("health_1")["status"] == "succeeded")
            assert worker.store.task("health_1")["result"]["url"] == "https://panel.example.com/"
            assert worker.runtime_status()["state"] == "degraded"
            assert worker.runtime_status()["available"]
        finally:
            await worker.stop()
    asyncio.run(run())


def test_unexpected_job_handler_bug_is_visible_without_killing_consumer(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    add_job(worker, "broken", "8.8.8.8")
    add_job(worker, "following", "1.1.1.1")
    execute = worker._execute
    async def fake_execute(job):
        if job["id"] == "broken":
            raise RuntimeError("unexpected handler bug")
        await execute(job)
    monkeypatch.setattr(worker, "_execute", fake_execute)
    async def fake_run(*args, **kwargs):
        return {"url": "https://panel.example.com/"}
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        try:
            await until(lambda: worker.store.task("following")["status"] == "succeeded")
            assert worker.runtime_status()["available"]
            assert worker.runtime_status()["state"] == "degraded"
            # The ambiguous operation is not automatically attempted again.
            assert worker.store.task("broken")["status"] == "interrupted"
            assert worker.store.task("broken")["encrypted_password"] is None
        finally:
            await worker.stop()
    asyncio.run(run())


def test_shutdown_stops_heartbeat_interrupts_only_running_and_keeps_queue(tmp_path, monkeypatch):
    worker = make_worker(tmp_path)
    add_job(worker, "running", "8.8.8.8")
    add_job(worker, "queued", "1.1.1.1")
    monkeypatch.setattr(worker_module, "HEARTBEAT_SECONDS", 0.02)
    async def fake_run(job, password, upload, emit, options):
        await emit("install", "正在安装。")
        await asyncio.Event().wait()
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        await worker.start()
        await until(lambda: worker.store.task("running")["stage"] == "install")
        await worker.stop()
        assert worker.store.task("running")["status"] == "interrupted"
        assert worker.store.task("running")["encrypted_password"] is None
        assert worker.store.task("queued")["status"] == "queued"
        assert worker.store.task("queued")["encrypted_password"] is not None
        before = len(worker.store.events("running"))
        await asyncio.sleep(0.06)
        assert len(worker.store.events("running")) == before
        assert worker.runtime_status()["active_jobs"] == 0
        assert worker.lock_file is None
    asyncio.run(run())


def test_direct_loop_remains_usable_with_worker_disabled_for_tests(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, enabled=False)
    add_job(worker)
    async def fake_run(*args, **kwargs):
        return {"url": "https://panel.example.com/"}
    monkeypatch.setattr(remote, "run_remote_job", fake_run)
    async def run():
        task = asyncio.create_task(worker.loop())
        try:
            await until(lambda: worker.store.task("health_1")["status"] == "succeeded")
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert worker.runtime_status()["state"] == "disabled"
    asyncio.run(run())
