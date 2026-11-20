"""Opt-in client for the isolated root-owned SentinelX fixed-operation broker.

This does not execute scripts or accept executable paths, cwd or environment.
Never surface broker tickets to logs or errors. Not enabled by default.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
from typing import Any

from sentinelx_core.executor import HandlerError

SOCKET = Path("/run/tohy-sentinelx-privileged-broker/broker.sock")
ALLOWED_OPERATIONS = frozenset({"audit-check", "audit-record"})
TICKET_FORMAT = re.compile(r"^[0-9a-f]{64}$")
REQUEST_LIMIT = 4096
RESPONSE_LIMIT = 4096
CALL_TIMEOUT = 10


def _refuse(reason: str) -> None:
    raise HandlerError("permission_denied", reason)


def _validate_socket() -> None:
    if sys.platform != "linux" or os.uname().nodename.split(".")[0] != "codex-dev":
        _refuse("privileged broker is unavailable on this host")
    if (os.geteuid(), os.getegid()) != (992, 990):
        _refuse("privileged broker requires its service identity")
    try:
        directory = SOCKET.parent.lstat()
        endpoint = SOCKET.lstat()
    except OSError:
        _refuse("privileged broker socket unavailable")
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != 0
        or directory.st_gid != 990
        or stat.S_IMODE(directory.st_mode) != 0o750
        or not stat.S_ISSOCK(endpoint.st_mode)
        or endpoint.st_uid != 0
        or endpoint.st_gid != 990
        or stat.S_IMODE(endpoint.st_mode) != 0o660
    ):
        _refuse("privileged broker socket identity invalid")


def _send(operation: str, ticket: str) -> dict[str, Any]:
    _validate_socket()
    data = json.dumps(
        {"version": 1, "action": "execute", "operation": operation, "ticket": ticket},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(data) > REQUEST_LIMIT:
        _refuse("broker request exceeds maximum size")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(CALL_TIMEOUT)
            connection.connect(str(SOCKET))
            peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", peer)
            if pid <= 0 or uid != 0 or gid != 0:
                _refuse("privileged broker peer identity invalid")
            connection.sendall(data)
            response = bytearray()
            while len(response) <= RESPONSE_LIMIT:
                chunk = connection.recv(min(512, RESPONSE_LIMIT + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in response:
                    break
    except (OSError, TimeoutError):
        _refuse("privileged broker communication unavailable")
    if (
        len(response) > RESPONSE_LIMIT
        or not response.endswith(b"\n")
        or response.count(b"\n") != 1
    ):
        _refuse("privileged broker response framing invalid")
    try:
        message = json.loads(response)
    except (ValueError, UnicodeError):
        _refuse("privileged broker response invalid")
    if not isinstance(message, dict) or type(message.get("ok")) is not bool:
        _refuse("privileged broker response schema invalid")
    # Ignore any server text. Never reflect a raw error or token back upstream.
    if message["ok"] is not True:
        _refuse("privileged broker rejected request")
    if (
        set(message) != {"ok", "operation", "completed"}
        or message.get("operation") != operation
        or message.get("completed") is not True
    ):
        _refuse("privileged broker success response invalid")
    return {"ok": True, "operation": operation, "completed": True}


def make_privileged_broker_handler():
    async def handle(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"operation", "ticket"}:
            _refuse("privileged operation fields invalid")
        operation = payload["operation"]
        ticket = payload["ticket"]
        if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
            _refuse("privileged operation not allowlisted")
        if not isinstance(ticket, str) or not TICKET_FORMAT.fullmatch(ticket):
            _refuse("privileged ticket format invalid")
        return await asyncio.to_thread(_send, operation, ticket)

    return handle
