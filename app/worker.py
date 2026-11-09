from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import os
import re
import time
from pathlib import Path

from app.config import Settings
from app.db import Store
from app.security import secret_box


HEARTBEAT_SECONDS = 15
QUEUE_POLL_SECONDS = 0.5
QUEUE_RETRY_SECONDS = 2
LOGGER = logging.getLogger(__name__)
STAGE_LABELS = {
    "starting": "执行准备", "preflight": "服务器检查", "backup": "数据备份",
    "install": "面板安装", "import": "数据库导入", "configure": "面板配置",
    "certificate": "证书申请", "bbr": "BBR 设置", "verify": "结果检查",
    "reboot": "服务器重启调度", "rollback": "失败恢复",
}


class JobWorker:
    def __init__(self, store: Store, settings: Settings) -> None:
        self.store, self.settings = store, settings
        self.box = secret_box(settings.secret)
        self.jobs: list[asyncio.Task] = []
        self.lock_file = None
        self._lock_owned = False
        self._consumers: list[asyncio.Task] = []
        self._active_jobs: set[str] = set()
        self._problems: dict[str, str] = {}
        self._started = False
        self._stopping = False
        self._stopped = False
        self._startup_error: str | None = None
        self._runner = None
        self._remote_options = None

    def runtime_status(self) -> dict:
        """Report actual consumers, rather than only the configured switch."""
        enabled = bool(self.settings.enable_worker)
        live = sum(not task.done() for task in self._consumers)
        available = enabled and self._started and not self._stopping and live > 0
        if not enabled:
            state, message = "disabled", "任务执行器未启用，请管理员开启后再提交任务。"
        elif self._startup_error:
            state, message = "failed", self._startup_error
        elif self._stopping:
            state, message = "stopping", "任务执行器正在停止，暂时不能提交新任务。"
        elif self._stopped:
            state, message = "stopped", "任务执行器已停止，请管理员重新启动。"
        elif not self._started:
            state, message = "starting", "任务执行器尚未准备完成，请稍后重试。"
        elif live == 0:
            state, message = "failed", "所有任务消费者均已退出，请管理员检查服务并重新启动。"
        elif live < self.settings.max_concurrent_jobs or self._problems:
            state, message = "degraded", next(iter(self._problems.values()), "部分任务消费者已退出，剩余消费者仍可执行任务。")
        else:
            state, message = "running", "任务执行器运行正常。"
        return {
            "enabled": enabled, "available": available, "state": state,
            "message": message, "active_jobs": len(self._active_jobs), "capacity": live,
        }

    def _load_runtime(self) -> None:
        """Import and construct dependencies before startup reports success."""
        module = importlib.import_module("app.remote")
        runner, options_type = getattr(module, "run_remote_job", None), getattr(module, "RemoteOptions", None)
        if not callable(runner) or not inspect.iscoroutinefunction(runner) or not callable(options_type):
            raise RuntimeError("远程执行模块缺少必要接口。")
        self._remote_options = options_type(
            allow_private_targets=self.settings.allow_private_targets,
            known_hosts_path=self.settings.data_dir / "ssh" / "known_hosts",
            command_timeout=900,
        )
        self._runner = runner

    def _acquire_lock(self) -> None:
        self.lock_file = (self.settings.data_dir / "worker.lock").open("a+b")
        self.lock_file.seek(0, 2)
        if not self.lock_file.tell():
            self.lock_file.write(b"0")
            self.lock_file.flush()
        self.lock_file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_owned = True
        except OSError:
            self.lock_file.close()
            self.lock_file = None
            raise RuntimeError("数据目录已有任务执行进程。请仅启动一个 Uvicorn worker。") from None

    def _release_lock(self) -> None:
        if self.lock_file is None:
            return
        try:
            if self._lock_owned:
                self.lock_file.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
        except OSError:
            LOGGER.warning("执行器文件锁释放时发生错误；正在关闭文件句柄。")
        finally:
            self.lock_file.close()
            self.lock_file = None
            self._lock_owned = False

    async def start(self) -> None:
        if self._started:
            return
        self._startup_error, self._stopped, self._stopping = None, False, False
        self._problems.clear()
        try:
            self._load_runtime()
            self.settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._acquire_lock()
            self.store.interrupt_running()
            ssh_dir = self.settings.data_dir / "ssh"
            ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            ssh_dir.chmod(0o700)
            self._consumers = [asyncio.create_task(self.loop(), name=f"deployment-worker-{i}")
                               for i in range(self.settings.max_concurrent_jobs)]
            self.jobs = [*self._consumers, asyncio.create_task(self.cleanup_loop(), name="upload-retention")]
            for task in self.jobs:
                task.add_done_callback(self._task_done)
            self._started = True
            await asyncio.sleep(0)
            if not any(not task.done() for task in self._consumers):
                raise RuntimeError("任务消费者启动后立即退出。")
        except BaseException:
            await self.stop()
            self._startup_error = "任务执行器启动失败，请管理员检查依赖、数据目录权限和进程日志。"
            raise

    def _task_done(self, task: asyncio.Task) -> None:
        if self._stopping:
            return
        failure = "任务消费者意外停止，请管理员检查服务；未自动重复执行远程任务。"
        if not task.cancelled():
            # Retrieve the exception without publishing potentially sensitive
            # third party error contents.
            exception = task.exception()
            if exception is not None:
                LOGGER.error("执行器后台任务退出：%s（%s）。", task.get_name(), type(exception).__name__)
        self._problems[task.get_name()] = failure

    async def stop(self) -> None:
        self._stopping = True
        try:
            for task in self.jobs:
                task.cancel()
            if self.jobs:
                await asyncio.gather(*self.jobs, return_exceptions=True)
        finally:
            self.jobs.clear()
            self._consumers.clear()
            self._release_lock()
            self._started, self._stopping, self._stopped = False, False, True

    async def loop(self) -> None:
        # Direct-loop use is retained for isolated tests and maintenance.
        if self._runner is None:
            self._load_runtime()
        current = asyncio.current_task()
        consumer = current.get_name() if current else "manual-consumer"
        while True:
            try:
                job = self.store.claim()
                self._problems.pop(consumer, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._problems[consumer] = "任务队列读取暂时失败，执行器正在自动重试，请管理员检查数据库。"
                LOGGER.warning("任务队列读取失败（%s）；将在下一轮重试。", type(exc).__name__)
                await asyncio.sleep(QUEUE_RETRY_SECONDS)
                continue
            if job is None:
                await asyncio.sleep(QUEUE_POLL_SECONDS)
                continue
            try:
                await self._execute(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._problems["job_handler"] = "任务处理出现异常，已停止该任务；请管理员核对任务日志，后续队列仍会继续处理。"
                LOGGER.error("任务处理异常（%s），消费者将继续处理队列。", type(exc).__name__)
                self._interrupt(job["id"], "任务处理出现异常，已停止且未自动重试。请核对目标服务器和任务日志。")
                self._active_jobs.discard(job["id"])

    async def _execute(self, job: dict) -> None:
        password = ""
        progress = {"stage": "starting", "since": time.monotonic()}
        heartbeat = None
        self._active_jobs.add(job["id"])

        def redact(value: object) -> str:
            message = str(value)
            if password:
                message = message.replace(password, "[SSH 密码已隐藏]")
            message = re.sub(r"(?i)(password|passwd|secret|token)\s*[=:]\s*[^\s]+", r"\1=[已隐藏]", message)
            return message[:2500]

        async def emit(stage: str, message: str) -> None:
            progress.update(stage=stage, since=time.monotonic())
            self.store.event(job["id"], stage, redact(message))

        async def beat() -> None:
            while True:
                await asyncio.sleep(HEARTBEAT_SECONDS)
                stage = str(progress["stage"])
                label = STAGE_LABELS.get(stage, "当前步骤")
                elapsed = max(0, int(time.monotonic() - progress["since"]))
                try:
                    # Keep the current business stage instead of introducing a
                    # generic heartbeat stage that would hide real progress.
                    if stage == "reboot":
                        self.store.event(job["id"], stage, f"{label}仍在执行，本步骤已等待 {elapsed} 秒；确认调度结果后即返回，不等待服务器重启回连。")
                    else:
                        self.store.event(job["id"], stage, f"{label}仍在执行，本步骤已等待 {elapsed} 秒；超时后会反馈原因。")
                except Exception as exc:
                    self._problems["persistence"] = "任务进度暂时无法写入，执行器仍在运行，请管理员检查数据库。"
                    LOGGER.warning("任务进度心跳记录失败（%s）。", type(exc).__name__)

        async def end_heartbeat() -> None:
            if heartbeat is not None:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)

        try:
            await emit("starting", "执行器已领取任务，正在检查账号并准备连接服务器。")
            heartbeat = asyncio.create_task(beat(), name=f"job-progress-{job['id']}")
            owner = self.store.user(job["user_id"])
            if not owner or not owner["active"]:
                raise RuntimeError("任务所属客户账号已停用，任务未执行。")
            password = self.box.decrypt(job["encrypted_password"].encode()).decode()
            result = await self._runner(
                job, password, Path(job["upload_path"]) if job.get("upload_path") else None,
                emit, options=self._remote_options,
            )
            await end_heartbeat()
            warnings = list(result.get("warnings") or [])
            warnings.extend((job.get("validation") or {}).get("warnings", []))
            if job["kind"] == "migrate":
                warnings.append("已完成重启前的面板访问、服务和数据库检查；账号、密码与双重验证沿用旧面板，未自动验证原账号登录。入站节点及订阅的实际连通性需要另行核对。")
            result["warnings"] = list(dict.fromkeys(warnings))
            self.store.finish(job["id"], result=result)
            try:
                completion = "搭建完成，面板已通过检查。"
                if job["kind"] == "migrate":
                    if result.get("reboot_scheduled") is True:
                        completion = "迁移完成，面板地址已返回，已安排服务器重启；重启期间请稍后访问。"
                    elif result.get("reboot_scheduled") is False:
                        completion = "迁移完成，面板地址已返回；自动重启未确认，请通过服务器控制台确认并在需要时手动重启。"
                    else:
                        completion = "迁移完成，面板地址已返回。"
                await emit("completed", completion)
                self._problems.pop("persistence", None)
            except Exception as event_exc:
                # A completed operation must not become retryable merely
                # because the optional final progress line could not be saved.
                self._problems["persistence"] = "任务已完成，但完成日志暂时无法写入，请管理员检查数据库。"
                LOGGER.warning("任务完成日志无法保存（%s）；已保留成功结果。", type(event_exc).__name__)
        except asyncio.CancelledError:
            await end_heartbeat()
            self._interrupt(job["id"])
            raise
        except Exception as exc:
            await end_heartbeat()
            message = redact(exc) or "执行失败，请查看阶段日志。"
            try:
                self.store.finish(job["id"], error=message)
                await emit("failed", message)
            except Exception as save_exc:
                self._problems["persistence"] = "任务已停止但状态写入失败，请管理员核对服务器和任务数据库。"
                LOGGER.error("任务失败状态无法保存（%s）；不会自动重试远程操作。", type(save_exc).__name__)
        finally:
            await end_heartbeat()
            self._active_jobs.discard(job["id"])
            password = ""

    def _interrupt(self, task_id: str, message: str = "执行进程正在停止。远程状态需重新检查，未自动重试。") -> None:
        try:
            self.store.interrupt_task(task_id, message)
        except Exception as exc:
            self._problems["persistence"] = "停止状态记录失败，请管理员检查任务和目标服务器。"
            LOGGER.error("任务中断状态无法保存（%s）。", type(exc).__name__)

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                cutoff = time.time() - self.settings.upload_retention_hours * 3600
                with self.store.connect() as db:
                    paths = db.execute("SELECT id,upload_path FROM tasks WHERE upload_path IS NOT NULL AND status NOT IN ('queued','running')").fetchall()
                    for row in paths:
                        path = Path(row["upload_path"])
                        try:
                            if path.exists() and path.stat().st_mtime > cutoff:
                                continue
                            path.unlink(missing_ok=True)
                            db.execute("UPDATE tasks SET upload_path=NULL WHERE id=?", (row["id"],))
                        except OSError:
                            LOGGER.warning("上传清理暂时失败，任务编号 %s；将在下一轮重试。", row["id"])
                self._problems.pop("cleanup", None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._problems["cleanup"] = "上传清理暂时失败，执行器仍在运行，请管理员检查数据目录。"
                LOGGER.warning("上传清理循环失败（%s）；将在下一轮重试。", type(exc).__name__)
