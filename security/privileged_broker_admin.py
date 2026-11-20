"""Root-only, fixed-operation administrative client for the staged broker.

This utility is never installed or called by the SentinelX agent. It uses
only the local Unix socket and carries no reusable bearer ticket.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import sys

from security.privileged_broker import HOST, SOCKET_DIR

SOCKET = SOCKET_DIR / "broker.sock"
OP_BY_ARG = {
    "audit-check": "audit-check",
    "audit-record": "audit-record",
}
RESPONSE_LIMIT = 4096


class ClientRejected(Exception):
    """Only non-sensitive diagnostics are exposed."""


def _reject(reason: str) -> None:
    raise ClientRejected(reason)


def _socket_is_trusted(filename: Path) -> None:
    try:
        parent = filename.parent.lstat()
        st = filename.lstat()
    except OSError:
        _reject("broker socket is unavailable")
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_gid != 990
        or stat.S_IMODE(parent.st_mode) != 0o750
        or not stat.S_ISSOCK(st.st_mode)
        or st.st_uid != 0
        or stat.S_IMODE(st.st_mode) != 0o660
    ):
        _reject("broker socket is untrusted")


def execute_local(operation: str, *, endpoint: Path = SOCKET) -> dict[str, str | bool]:
    if os.geteuid() != 0 or os.uname().nodename.split(".")[0] != HOST:
        _reject("trusted root host identity required")
    if operation not in OP_BY_ARG:
        _reject("operation not allowlisted")
    _socket_is_trusted(endpoint)
    request_id = secrets.token_hex(16)
    body = {
        "version": 1,
        "action": "run",
        "operation": OP_BY_ARG[operation],
        "request_id": request_id,
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(40)
            sock.connect(str(endpoint))
            cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", cred)
            if pid <= 0 or uid != 0 or gid != 0:
                _reject("root broker peer identity invalid")
            sock.sendall((json.dumps(body, sort_keys=True) + "\n").encode("utf-8"))
            reply = bytearray()
            while len(reply) <= RESPONSE_LIMIT:
                part = sock.recv(min(512, RESPONSE_LIMIT + 1 - len(reply)))
                if not part:
                    break
                reply.extend(part)
                if b"\n" in reply:
                    break
    except (OSError, TimeoutError):
        _reject("broker execution status unavailable")
    if len(reply) > RESPONSE_LIMIT or not reply.endswith(b"\n") or reply.count(b"\n") != 1:
        _reject("broker response invalid")
    try:
        message = json.loads(reply)
    except (UnicodeError, ValueError):
        _reject("broker response malformed")
    if (
        not isinstance(message, dict)
        or set(message) != {"ok", "operation", "completed", "request_id"}
        or message["ok"] is not True
        or message["operation"] != operation
        or message["completed"] is not True
        or message["request_id"] != request_id
    ):
        # Execution may already have started or even completed. Never
        # automatically retry a root operation after a response failure.
        _reject("root execution unconfirmed; inspect read-only receipts")
    return {
        "ok": True,
        "operation": operation,
        "request_id": request_id,
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in OP_BY_ARG:
        print("usage: privileged_broker_admin.py audit-check|audit-record", file=sys.stderr)
        return 2
    try:
        result = execute_local(args[0])
    except ClientRejected as exc:
        print("BROKER_ADMIN_BLOCKED:", str(exc), file=sys.stderr)
        return 3
    # Only correlation metadata; never a bearer token, raw stdout or secret.
    print("BROKER_ADMIN_ACCEPTED", result["operation"], result["request_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
