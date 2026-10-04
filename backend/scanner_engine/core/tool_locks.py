from __future__ import annotations

import contextlib
import fcntl
from pathlib import Path

from django.conf import settings


@contextlib.contextmanager
def tool_lock(tool_name: str, exclusive: bool, blocking: bool = True):
    lock_dir = Path(getattr(settings, "TOOL_LOCK_DIR", settings.SCANNER_WORK_DIR.parent / "tool_locks"))
    lock_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in tool_name)
    lock_path = lock_dir / f"{safe_name}.lock"
    with lock_path.open("a+") as handle:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(handle.fileno(), operation)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
