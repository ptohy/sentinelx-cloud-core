"""File times from read and list are UTC with a +0000 label (sxrep_1YBCB7HSZG1F).

read's modified_at and list's mtime were built with time.strftime("%z",
time.gmtime(ts)). On Windows %z writes the machine's local offset, not the
struct's, so a Windows host returned the UTC digits labelled -0800. Linux
can't show that on its own, so the tests also make time.strftime behave like
Windows: %z becomes a local offset. The value must still say +0000 and mean
the file's real instant.
"""

from __future__ import annotations

import os
import time
from datetime import datetime

import pytest

from sentinelx_core.handlers import fileops
from sentinelx_core.handlers.fileops import make_list_handler, make_read_handler
from sentinelx_core.policy import Policy

MTIME = 1794536720  # 2026-11-13T02:25:20 UTC
_real_strftime = time.strftime


def _windows_strftime(fmt, *args):
    # What the Windows C runtime does with %z: the machine's local offset,
    # whatever the struct says.
    return _real_strftime(fmt.replace("%z", "-0800"), *args)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    f = root / "ACTUAL_OWNER_INPUT517.json"
    f.write_text("{}\n")
    os.utime(f, (MTIME, MTIME))
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"allowed_commands: []\nfile_ops:\n  paths:\n    - path: {root}\n      access: r\n")
    return root, f, Policy.from_file(cfg)


@pytest.fixture(params=["linux", "windows"])
def platform_strftime(request, monkeypatch):
    if request.param == "windows":
        monkeypatch.setattr(fileops.time, "strftime", _windows_strftime)
    return request.param


def _check(value: str) -> None:
    assert value == "2026-11-13T02:25:20+0000"
    assert datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z").timestamp() == MTIME


async def test_read_modified_at_is_utc(tree, platform_strftime):
    root, f, pol = tree
    r = await make_read_handler(pol)({"path": str(f)})
    _check(r["modified_at"])


async def test_list_mtime_is_utc(tree, platform_strftime):
    root, f, pol = tree
    r = await make_list_handler(pol)({"path": str(root)})
    [entry] = r["entries"]
    _check(entry["mtime"])
