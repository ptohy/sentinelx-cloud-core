"""Admin client is local root-only; no remote token or arbitrary command path."""
from __future__ import annotations

import json
import socket
import struct
from types import SimpleNamespace

import pytest

from security import privileged_broker_admin as admin


def _allow_host(monkeypatch):
    monkeypatch.setattr(admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(admin.os, "uname", lambda: SimpleNamespace(nodename="codex-dev"))
    monkeypatch.setattr(admin, "_socket_is_trusted", lambda _: None)
    monkeypatch.setattr(admin.secrets, "token_hex", lambda length: "c" * 32)


class FakeSocket:
    def __init__(self, *, peer_uid=0, peer_gid=0, bad_reply=None):
        self.peer_uid = peer_uid
        self.peer_gid = peer_gid
        self.bad_reply = bad_reply
        self.sent = None
        self.read = False
        self.path = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, value):
        assert value <= 40

    def connect(self, path):
        self.path = path

    def getsockopt(self, level, field, size):
        assert level == socket.SOL_SOCKET
        assert field == socket.SO_PEERCRED
        return struct.pack("3i", 1234, self.peer_uid, self.peer_gid)

    def sendall(self, data):
        self.sent = json.loads(data)
        assert self.sent["version"] == 1
        assert self.sent["action"] == "run"
        assert set(self.sent) == {"version", "action", "request_id", "operation"}

    def recv(self, size):
        if self.read:
            return b""
        self.read = True
        if self.bad_reply is not None:
            return self.bad_reply
        return (
            json.dumps({
                "ok": True,
                "operation": self.sent["operation"],
                "completed": True,
                "request_id": self.sent["request_id"],
            }) + "\n"
        ).encode()


def test_nonroot_client_never_connects(monkeypatch):
    monkeypatch.setattr(admin.os, "geteuid", lambda: 992)
    monkeypatch.setattr(admin.os, "uname", lambda: SimpleNamespace(nodename="codex-dev"))
    with pytest.raises(admin.ClientRejected, match="root host"):
        admin.execute_local("audit-check")


@pytest.mark.parametrize("value", ["arbitrary-shell", "sudo", "", "audit-check --unsafe"])
def test_unknown_operation_never_connects(monkeypatch, value):
    _allow_host(monkeypatch)
    with pytest.raises(admin.ClientRejected, match="allowlisted"):
        admin.execute_local(value)


def test_admin_sends_only_root_operation_and_request_identity(monkeypatch):
    _allow_host(monkeypatch)
    fake = FakeSocket()
    monkeypatch.setattr(admin.socket, "socket", lambda *_: fake)
    received = admin.execute_local("audit-check")
    assert received["ok"] is True
    assert received["request_id"] == "c" * 32
    assert fake.sent == {
        "version": 1,
        "action": "run",
        "operation": "audit-check",
        "request_id": "c" * 32,
    }


def test_admin_rejects_untrusted_broker_peer(monkeypatch):
    _allow_host(monkeypatch)
    fake = FakeSocket(peer_uid=992)
    monkeypatch.setattr(admin.socket, "socket", lambda *_: fake)
    with pytest.raises(admin.ClientRejected, match="peer identity"):
        admin.execute_local("audit-record")
    assert fake.sent is None


@pytest.mark.parametrize(
    "response",
    [
        b'{"ok":false,"reason":"something failed"}\n',
        b'{"ok":true,"operation":"audit-check","completed":true,"request_id":"wrong"}\n',
        b'{"ok":true,"operation":"audit-check","completed":true,"request_id":"c"}\n',
        b'{}',
        b'invalid json\n',
    ],
)
def test_unknown_response_never_produces_success(monkeypatch, response):
    _allow_host(monkeypatch)
    fake = FakeSocket(bad_reply=response)
    monkeypatch.setattr(admin.socket, "socket", lambda *_: fake)
    with pytest.raises(admin.ClientRejected):
        admin.execute_local("audit-check")


def test_missing_socket_fails_closed(monkeypatch, tmp_path):
    _allow_host(monkeypatch)
    monkeypatch.undo()
    monkeypatch.setattr(admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(admin.os, "uname", lambda: SimpleNamespace(nodename="codex-dev"))
    with pytest.raises(admin.ClientRejected, match="unavailable"):
        admin.execute_local("audit-check", endpoint=tmp_path / "absent.sock")


@pytest.mark.parametrize("argv", [[], ["audit-check", "extra"], ["shell"], ["--help"]])
def test_no_cli_extras_allowed(argv, capsys):
    assert admin.main(argv) == 2
    assert "usage" in capsys.readouterr().err


def test_shell_output_never_contains_bearer_token(monkeypatch, capsys):
    _allow_host(monkeypatch)
    fake = FakeSocket()
    monkeypatch.setattr(admin.socket, "socket", lambda *_: fake)
    assert admin.main(["audit-check"]) == 0
    out = capsys.readouterr().out
    assert "BROKER_ADMIN_ACCEPTED" in out
    assert "ticket" not in out.lower()
    assert "c" * 32 in out
