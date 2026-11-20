"""Opt-in admission check for privileged script_run requests.

This is application-level admission, NOT an OS privilege boundary. A root
broker and a least-privilege sudo policy are required before relying on it for
security isolation: an unprivileged script can itself invoke sudo while broad
NOPASSWD remains configured.

Only a root-owned, non-writable manifest at a fixed path can approve an exact
request fingerprint, with a maximum approval lifetime of one hour.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

APPROVAL_PATH = Path("/etc/sentinelx/privileged-script-approvals.json")
MAX_MANIFEST_BYTES = 65536
MAX_APPROVALS = 128
MAX_APPROVAL_LIFETIME = dt.timedelta(hours=1)
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class AdmissionDenied(Exception):
    """A privileged request is not approved. Never includes submitted code."""


def request_fingerprint(
    *,
    interpreter: str,
    content: str,
    args: list[str],
    cwd: str | None,
    env: dict[str, str],
    timeout: int,
    background: bool,
) -> str:
    """Bind the full privileged request, including secret env values, by hash."""
    if not isinstance(content, str) or not isinstance(interpreter, str):
        raise AdmissionDenied("invalid privileged script identity")
    data = {
        "schema": 1,
        "interpreter": interpreter,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "args": args,
        "cwd": cwd,
        "env": env,
        "timeout": timeout,
        "background": background,
    }
    try:
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (ValueError, TypeError):
        raise AdmissionDenied("invalid privileged request fields") from None
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _approval_manifest() -> dict[str, Any]:
    """Read a trusted root-owned manifest, no symlink-following or unbounded IO."""
    parent = APPROVAL_PATH.parent
    try:
        parent_stat = parent.lstat()
    except OSError:
        raise AdmissionDenied("privileged approvals unavailable") from None
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != 0
        or parent_stat.st_mode & 0o022
    ):
        raise AdmissionDenied("privileged approvals directory untrusted")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(APPROVAL_PATH, flags)
    except OSError:
        raise AdmissionDenied("privileged approvals unavailable") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > MAX_MANIFEST_BYTES
        ):
            raise AdmissionDenied("privileged approvals file untrusted")
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES or len(raw) != info.st_size:
            raise AdmissionDenied("privileged approvals file changed during read")
    finally:
        os.close(fd)
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        raise AdmissionDenied("privileged approvals malformed") from None
    if not isinstance(obj, dict):
        raise AdmissionDenied("privileged approvals malformed")
    return obj


def _time(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise AdmissionDenied("privileged approval timestamp missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AdmissionDenied("privileged approval timestamp invalid") from None
    if parsed.tzinfo is None:
        raise AdmissionDenied("privileged approval timestamp must have timezone")
    return parsed.astimezone(dt.timezone.utc)


def approved(fingerprint: str, manifest: dict[str, Any], *, now: dt.datetime | None = None) -> bool:
    """Deny on any malformed approval manifest; no wildcard, prefix or fallback."""
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise AdmissionDenied("privileged request fingerprint invalid")
    if set(manifest) != {"schema", "approvals"} or manifest["schema"] != 1:
        raise AdmissionDenied("privileged approval schema unsupported")
    approvals = manifest["approvals"]
    if not isinstance(approvals, list) or len(approvals) > MAX_APPROVALS:
        raise AdmissionDenied("privileged approval entry count invalid")
    reference = now if now is not None else dt.datetime.now(dt.timezone.utc)
    if reference.tzinfo is None:
        raise AdmissionDenied("clock timezone missing")
    reference = reference.astimezone(dt.timezone.utc)
    seen: set[str] = set()
    allow = False
    for item in approvals:
        if not isinstance(item, dict) or set(item) != {"fingerprint", "issued_at", "expires_at"}:
            raise AdmissionDenied("privileged approval entry invalid")
        key = item["fingerprint"]
        if not isinstance(key, str) or not FINGERPRINT_RE.fullmatch(key) or key in seen:
            raise AdmissionDenied("privileged approval fingerprint invalid or duplicated")
        seen.add(key)
        issued = _time(item["issued_at"])
        expires = _time(item["expires_at"])
        if expires <= issued or expires - issued > MAX_APPROVAL_LIFETIME:
            raise AdmissionDenied("privileged approval lifetime invalid")
        if key == fingerprint and issued <= reference < expires:
            allow = True
    return allow


def enforce(
    mode: str,
    *,
    interpreter: str,
    content: str,
    args: list[str],
    cwd: str | None,
    env: dict[str, str],
    timeout: int,
    background: bool,
) -> None:
    """Called before staging. Defaults to legacy for deployed compatibility."""
    if mode == "legacy":
        return
    if mode == "deny":
        raise AdmissionDenied("privileged script_run denied by policy")
    if mode != "approval":
        raise AdmissionDenied("privileged script_run policy invalid")
    fingerprint = request_fingerprint(
        interpreter=interpreter,
        content=content,
        args=args,
        cwd=cwd,
        env=env,
        timeout=timeout,
        background=background,
    )
    if not approved(fingerprint, _approval_manifest()):
        raise AdmissionDenied("privileged script_run requires current exact approval")
