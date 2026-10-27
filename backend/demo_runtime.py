"""Restricted demonstration policy and bounded synchronous jobs (no network I/O)."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import threading
from fastapi import HTTPException


def restricted_demo():
    mode = os.environ.get("QR_SHIELD_MODE", "development")
    if mode not in {"development", "restricted-demo"}:
        raise RuntimeError("Invalid QR_SHIELD_MODE")
    return mode == "restricted-demo"


def load_production_model(loader):
    path = Path(os.environ.get("MODEL_PATH", str(Path(__file__).with_name("phishing_model_v2.pkl"))))
    if restricted_demo():
        expected = os.environ.get("MODEL_SHA256", "")
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise RuntimeError("Restricted demo requires a trusted MODEL_SHA256")
        with path.open("rb") as artifact:
            actual = hashlib.file_digest(artifact, "sha256").hexdigest()
        if actual != expected:
            raise RuntimeError("Production model integrity check failed")
    return loader(str(path))


class BoundedJob:
    """Keep the slot until native work really exits, including after HTTP timeout."""
    def __init__(self, name, timeout):
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=name)
        self.slot = threading.BoundedSemaphore(1)
        self.timeout = timeout

    async def run(self, function, *args):
        if not self.slot.acquire(blocking=False):
            raise HTTPException(503, "Demo processing slot is busy; retry later")
        try:
            future = self.pool.submit(function, *args)
        except BaseException:
            self.slot.release()
            raise
        future.add_done_callback(lambda _: self.slot.release())
        wrapped = asyncio.wrap_future(future)
        # Consume late errors after a timed-out client; never start another native job.
        wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            return await asyncio.wait_for(asyncio.shield(wrapped), self.timeout)
        except asyncio.TimeoutError:
            raise HTTPException(504, "Demo processing timed out; no additional job was started") from None


scan_jobs = BoundedJob("qr-scan", 30)
report_jobs = BoundedJob("qr-report", 20)
history_jobs = BoundedJob("qr-history", 10)
