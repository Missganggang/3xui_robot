import asyncio

import pytest

from app.cloudflare import CloudflareError
from app.dns_locks import zone_write_lock


def test_zone_write_lock_waits_times_out_and_is_available_after_release(tmp_path):
    async def run():
        async with zone_write_lock(tmp_path, "account", "zone"):
            with pytest.raises(CloudflareError) as error:
                async with zone_write_lock(tmp_path, "account", "zone", timeout=0.02):
                    pytest.fail("same-zone lock unexpectedly acquired")
            assert error.value.status_code == 409
            async with zone_write_lock(tmp_path, "account", "other-zone", timeout=0.02):
                pass
        async with zone_write_lock(tmp_path, "account", "zone", timeout=0.02):
            pass
    asyncio.run(run())


def test_cancelling_a_waiter_closes_its_handle_and_does_not_release_another_writer(tmp_path):
    async def contender():
        async with zone_write_lock(tmp_path, "account", "zone", timeout=1):
            pytest.fail("waiter entered before the active writer released the lock")
    async def run():
        async with zone_write_lock(tmp_path, "account", "zone"):
            waiting = asyncio.create_task(contender())
            await asyncio.sleep(0.02)
            waiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting
            with pytest.raises(CloudflareError):
                async with zone_write_lock(tmp_path, "account", "zone", timeout=0.02):
                    pytest.fail("cancelled waiter released the active writer's lock")
        async with zone_write_lock(tmp_path, "account", "zone", timeout=0.02):
            pass
    asyncio.run(run())
