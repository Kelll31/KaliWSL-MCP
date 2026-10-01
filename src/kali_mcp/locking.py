"""Prevent two stdio server instances from mutating the same workspace."""

import os
from pathlib import Path


class WorkspaceLock:
    def __init__(self, root: Path):
        self.file = (root / ".server.lock").open("a+b")
        if self.file.tell() == 0:
            self.file.write(b"\0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt

                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            raise ValueError(
                "Workspace is already used by another server; use a separate "
                "workspace for each MCP connection"
            ) from None

    def close(self) -> None:
        self.file.close()
