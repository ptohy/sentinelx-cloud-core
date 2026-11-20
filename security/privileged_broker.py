"""Prototype root-side broker for TWO fixed, pre-existing audit operations.

Not installed as a service. Not a security boundary while the SentinelX
account retains NOPASSWD: ALL. Tickets are root-issued, identity-bound,
time-limited, and consumed once in SQLite before invoking fixed argv.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import time
from typing import Any

VERSION = 1
HOST = "codex-dev"
AGENT_UID = 992
AGENT_GID = 990
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 32768
MAX_TTL_SECONDS = 300
CLIENT_TIMEOUT_SECONDS = 5
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
COMMAND_TIMEOUT_SECONDS = 35
SOCKET_DIR = Path("/run/tohy-sentinelx-privileged-broker")
DB_DIR = Path("/var/lib/tohy-sentinelx-privileged-broker")
HELPER = Path("/usr/local/sbin/tohy-sentinelx-governed-admin")
OPERATIONS: dict[str, tuple[str, ...]] = {
    "audit-check": (str(HELPER), "audit-check"),
    "audit-record": (str(HELPER), "audit-record"),
}


class Rejected(Exception):
    """A fixed, non-sensitive rejection; never reflect request values."""


def reject(message: str) -> None:
    raise Rejected(message)


def _is_root_regular(path: Path, mode: int) -> bool:
    try:
        s = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(s.st_mode)
        and s.st_uid == 0
        and stat.S_IMODE(s.st_mode) == mode
        and s.st_nlink == 1
    )


def prepare_dir(path: Path, mode: int, gid: int) -> None:
    """Fail closed on pre-existing non-trusted paths; no symlinks."""
    if not path.is_absolute():
        reject("broker directory must be absolute")
    if not path.exists() and not path.is_symlink():
        try:
            path.mkdir(mode=mode)
            os.chown(path, 0, gid)
            os.chmod(path, mode)
        except OSError:
            reject("unable to prepare trusted broker directory")
    try:
        st = path.lstat()
    except OSError:
        reject("broker directory unavailable")
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != 0
        or st.st_gid != gid
        or stat.S_IMODE(st.st_mode) != mode
        or st.st_nlink < 2
    ):
        reject("broker directory identity invalid")


def _trusted_parent(path: Path) -> None:
    """No externally supplied parent directory may be traversed to root assets."""
    parent = path.parent
    if not parent.is_absolute():
        reject("invalid broker path")
    st = parent.lstat()
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != 0
        or st.st_mode & 0o022
    ):
        reject("broker parent untrusted")


def current_boot_id() -> str:
    """Tickets must not survive a machine restart."""
    try:
        boot = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except OSError:
        reject("host boot identity unavailable")
    if not __import__("re").fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        boot,
    ):
        reject("host boot identity invalid")
    return boot


class TicketStore:
    def __init__(self, filename: Path) -> None:
        self.filename = filename
        self.boot_id = current_boot_id()
        _trusted_parent(filename)
        if filename.exists() or filename.is_symlink():
            if not _is_root_regular(filename, 0o600):
                reject("ticket database untrusted")
        # Root-only database, with durable SQLite transactions.
        self.db = sqlite3.connect(str(filename), timeout=5, isolation_level=None)
        os.chmod(filename, 0o600)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS tickets("
            "digest TEXT PRIMARY KEY, operation TEXT NOT NULL,"
            "uid INTEGER NOT NULL, gid INTEGER NOT NULL,"
            "boot_id TEXT NOT NULL, issued_ns INTEGER NOT NULL, expires_ns INTEGER NOT NULL,"
            "consumed_ns INTEGER)"
        )

    def issue(
        self, operation: str, uid: int, gid: int, ttl_seconds: int,
        *, now_ns: int | None = None,
    ) -> str:
        if operation not in OPERATIONS:
            reject("operation not allowlisted")
        if type(uid) is not int or type(gid) is not int or (uid, gid) != (AGENT_UID, AGENT_GID):
            reject("target identity not allowlisted")
        if type(ttl_seconds) is not int or not (1 <= ttl_seconds <= MAX_TTL_SECONDS):
            reject("ticket lifetime invalid")
        current = time.time_ns() if now_ns is None else now_ns
        ticket = secrets.token_hex(32)
        digest = hashlib.sha256(bytes.fromhex(ticket)).hexdigest()
        self.db.execute(
            "INSERT INTO tickets VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            (digest, operation, uid, gid, self.boot_id,
             current, current + ttl_seconds * 1_000_000_000),
        )
        return ticket

    def consume(
        self, token: str, operation: str, uid: int, gid: int,
        *, now_ns: int | None = None,
    ) -> bool:
        if operation not in OPERATIONS or type(uid) is not int or type(gid) is not int:
            return False
        if not isinstance(token, str) or len(token) != 64:
            return False
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            return False
        if token != token.lower():
            return False
        digest = hashlib.sha256(raw).hexdigest()
        current = time.time_ns() if now_ns is None else now_ns
        try:
            self.db.execute("BEGIN IMMEDIATE")
            cur = self.db.execute(
                "UPDATE tickets SET consumed_ns=? "
                "WHERE digest=? AND operation=? AND uid=? AND gid=? "
                "AND consumed_ns IS NULL AND boot_id=? AND issued_ns<=? AND expires_ns>?",
                (current, digest, operation, uid, gid, self.boot_id, current, current),
            )
            success = cur.rowcount == 1
            self.db.execute("COMMIT")
            return success
        except (sqlite3.Error, OSError):
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            reject("ticket store unavailable")


def _peercred(connection: socket.socket) -> tuple[int, int, int]:
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        reject("peer credentials unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        reject("invalid peer credentials")
    return pid, uid, gid


def _read_request(connection: socket.socket) -> dict[str, Any]:
    data = bytearray()
    connection.settimeout(CLIENT_TIMEOUT_SECONDS)
    while len(data) <= MAX_REQUEST_BYTES:
        part = connection.recv(min(1024, MAX_REQUEST_BYTES + 1 - len(data)))
        if not part:
            reject("incomplete request")
        data.extend(part)
        if b"\n" in data:
            break
    if len(data) > MAX_REQUEST_BYTES or data.count(b"\n") != 1 or not data.endswith(b"\n"):
        reject("request too large or invalid framing")
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        reject("request JSON invalid")
    if not isinstance(obj, dict) or type(obj.get("version")) is not int or obj["version"] != VERSION:
        reject("request schema unsupported")
    return obj


def _fixed_operation(operation: str) -> dict[str, Any]:
    """Only immutable argv; never a shell, dynamic path, user-provided env or cwd."""
    if operation not in OPERATIONS or not _is_root_regular(HELPER, 0o755):
        reject("trusted operation unavailable")
    try:
        done = subprocess.run(
            OPERATIONS[operation],
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        reject("fixed operation unavailable")
    if done.returncode != 0:
        reject("fixed operation failed")
    # Do not surface unbounded privileged command output to an untrusted caller.
    return {"ok": True, "operation": operation, "completed": True}


class Broker:
    def __init__(self, socket_dir: Path, database_dir: Path) -> None:
        if os.geteuid() != 0 or os.uname().nodename.split(".")[0] != HOST:
            reject("root on the dedicated host required")
        prepare_dir(socket_dir, 0o750, AGENT_GID)
        prepare_dir(database_dir, 0o700, 0)
        self.socket_file = socket_dir / "broker.sock"
        if self.socket_file.exists() or self.socket_file.is_symlink():
            reject("broker socket already exists; never replace an active listener")
        self.store = TicketStore(database_dir / "tickets.sqlite3")

    def handle(self, obj: dict[str, Any], uid: int, gid: int) -> dict[str, Any]:
        if obj.get("action") == "issue":
            if set(obj) != {"version", "action", "operation", "target_uid", "target_gid", "ttl_seconds"}:
                reject("issue request fields invalid")
            if uid != 0:
                reject("root identity required to issue tickets")
            token = self.store.issue(
                obj["operation"], obj["target_uid"], obj["target_gid"], obj["ttl_seconds"]
            )
            return {"ok": True, "ticket": token, "expires_in_seconds": obj["ttl_seconds"]}
        if obj.get("action") == "execute":
            if set(obj) != {"version", "action", "operation", "ticket"}:
                reject("execute request fields invalid")
            if (uid, gid) != (AGENT_UID, AGENT_GID):
                reject("authorized service identity required")
            operation = obj["operation"]
            if not self.store.consume(obj["ticket"], operation, uid, gid):
                reject("ticket missing, expired, mismatched or already consumed")
            return _fixed_operation(operation)
        reject("unknown broker action")

    def serve(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(10)
            listener.bind(str(self.socket_file))
            os.chown(self.socket_file, 0, AGENT_GID)
            os.chmod(self.socket_file, 0o660)
            listener.listen(12)
            while True:
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    try:
                        _, uid, gid = _peercred(conn)
                        obj = _read_request(conn)
                        reply = self.handle(obj, uid, gid)
                    except (Rejected, OSError, ValueError, TypeError, KeyError) as exc:
                        # No user-controlled fields in errors.
                        reply = {"ok": False, "reason": str(exc) if isinstance(exc, Rejected) else "invalid request"}
                    encoded = json.dumps(reply, sort_keys=True).encode("utf-8") + b"\n"
                    if len(encoded) > MAX_RESPONSE_BYTES:
                        encoded = b'{"ok":false,"reason":"response bounded"}\n'
                    try:
                        conn.sendall(encoded)
                    except OSError:
                        continue


def main() -> None:
    if sys.argv != [sys.argv[0], "--serve"]:
        reject("only --serve is supported")
    Broker(SOCKET_DIR, DB_DIR).serve()


if __name__ == "__main__":
    try:
        main()
    except Rejected as exc:
        print("BROKER_BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(2)
