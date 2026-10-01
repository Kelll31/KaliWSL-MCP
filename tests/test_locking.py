import pytest

from kali_mcp.locking import WorkspaceLock


def test_exclusive_workspace_lock(tmp_path):
    first = WorkspaceLock(tmp_path)
    try:
        with pytest.raises(ValueError, match="already used"):
            WorkspaceLock(tmp_path)
    finally:
        first.close()
    second = WorkspaceLock(tmp_path)
    second.close()
