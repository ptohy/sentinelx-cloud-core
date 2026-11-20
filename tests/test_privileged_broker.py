"""Standalone root broker tests. All fixed operations are mocked or inspected.

No live service, sudoers, root process or production paths are modified.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket

import pytest

from security import privileged_broker as broker


@pytest.fixture
def store(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(broker, "_trusted_parent", lambda _: None)
    monkeypatch.setattr(broker, "_is_root_regular", lambda _path, _mode: True)
    return broker.TicketStore(tmp_path / "tickets.sqlite3")


def test_ticket_consumed_exactly_once(store):
    t = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 30, now_ns=100_000_000_000)
    assert store.consume(t, "audit-check", broker.AGENT_UID, broker.AGENT_GID, now_ns=101_000_000_000)
    assert not store.consume(t, "audit-check", broker.AGENT_UID, broker.AGENT_GID, now_ns=102_000_000_000)


@pytest.mark.parametrize("change", ["wrong_operation", "wrong_uid", "wrong_gid", "future", "expired", "malformed"])
def test_ticket_binding_denied(store, change):
    now = 100_000_000_000
    ticket = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 30, now_ns=now)
    args = [ticket, "audit-check", broker.AGENT_UID, broker.AGENT_GID]
    timestamp = now + 1_000_000_000
    if change == "wrong_operation":
        args[1] = "audit-record"
    elif change == "wrong_uid":
        args[2] = 1000
    elif change == "wrong_gid":
        args[3] = 1000
    elif change == "future":
        timestamp = now - 1_000_000_000
    elif change == "expired":
        timestamp = now + 30_000_000_000
    else:
        args[0] = "not-an-authorized-ticket"
    assert not store.consume(*args, now_ns=timestamp)
    assert store.consume(ticket, "audit-check", broker.AGENT_UID, broker.AGENT_GID, now_ns=now + 2_000_000_000)


@pytest.mark.parametrize("uid,gid", [(0, 0), (1000, 1000), (992, 0), (992, 991)])
def test_reject_ticket_for_different_target_identity(store, uid, gid):
    with pytest.raises(broker.Rejected):
        store.issue("audit-check", uid, gid, 30)


@pytest.mark.parametrize("ttl", [-1, 0, 301, 30.5, True])
def test_invalid_expiration_rejected(store, ttl):
    with pytest.raises(broker.Rejected):
        store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, ttl)


def test_insertion_rejects_unknown_operation(store):
    with pytest.raises(broker.Rejected):
        store.issue("execute-root-shell", broker.AGENT_UID, broker.AGENT_GID, 30)


def test_ticket_cannot_cross_a_host_reboot(store):
    token = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 60)
    actual = store.boot_id
    store.boot_id = "00000000-0000-0000-0000-000000000000"
    assert not store.consume(token, "audit-check", broker.AGENT_UID, broker.AGENT_GID)
    store.boot_id = actual
    assert store.consume(token, "audit-check", broker.AGENT_UID, broker.AGENT_GID)


def test_db_never_stores_bearer_token(store):
    token = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 30)
    rows = list(store.db.execute("SELECT digest, operation FROM tickets"))
    assert len(rows) == 1
    assert rows[0][0] != token
    assert token not in str(rows)


def test_database_replay_blocked_across_separate_connections(store, monkeypatch):
    token = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 60)
    filename = store.filename

    def compete(_):
        other = broker.TicketStore(filename)
        try:
            return other.consume(token, "audit-check", broker.AGENT_UID, broker.AGENT_GID)
        finally:
            other.db.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(compete, range(18)))
    assert sum(results) == 1


def test_broker_issues_only_to_root(store):
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    request = {
        "version": 1, "action": "issue", "operation": "audit-check",
        "target_uid": broker.AGENT_UID, "target_gid": broker.AGENT_GID, "ttl_seconds": 60,
    }
    with pytest.raises(broker.Rejected, match="root identity"):
        b.handle(request, broker.AGENT_UID, broker.AGENT_GID)
    with pytest.raises(broker.Rejected, match="fields"):
        b.handle({**request, "sudo": True}, 0, 0)
    result = b.handle(request, 0, 0)
    assert result["ok"]
    assert len(result["ticket"]) == 64


def test_broker_executes_only_for_matching_service_identity(store, monkeypatch):
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    t = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 60)
    request = {"version": 1, "action": "execute", "operation": "audit-check", "ticket": t}
    effects = []
    monkeypatch.setattr(broker, "_fixed_operation", lambda name: effects.append(name) or {"ok": True})
    with pytest.raises(broker.Rejected, match="authorized service"):
        b.handle(request, 0, 0)
    with pytest.raises(broker.Rejected, match="fields"):
        b.handle({**request, "arbitrary_argv": ["/bin/bash"]}, broker.AGENT_UID, broker.AGENT_GID)
    assert b.handle(request, broker.AGENT_UID, broker.AGENT_GID) == {"ok": True}
    assert effects == ["audit-check"]
    with pytest.raises(broker.Rejected, match="already consumed"):
        b.handle(request, broker.AGENT_UID, broker.AGENT_GID)
    assert effects == ["audit-check"]


def test_ticket_consumed_even_when_effect_fails(store, monkeypatch):
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    t = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 60)
    req = {"version": 1, "action": "execute", "operation": "audit-check", "ticket": t}

    def failed(_):
        raise broker.Rejected("fixed operation failed")

    monkeypatch.setattr(broker, "_fixed_operation", failed)
    with pytest.raises(broker.Rejected, match="fixed operation failed"):
        b.handle(req, broker.AGENT_UID, broker.AGENT_GID)
    with pytest.raises(broker.Rejected, match="already consumed"):
        b.handle(req, broker.AGENT_UID, broker.AGENT_GID)


def test_fixed_operation_has_no_dynamic_shell_argv(monkeypatch):
    monkeypatch.setattr(broker, "_is_root_regular", lambda *_: True)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": "secret", "stderr": ""})()

    monkeypatch.setattr(broker.subprocess, "run", run)
    assert broker._fixed_operation("audit-check") == {
        "ok": True, "operation": "audit-check", "completed": True,
    }
    args, options = calls[0]
    assert args == (str(broker.HELPER), "audit-check")
    assert options.get("cwd") == "/"
    assert options.get("stdin") is not None
    assert options.get("shell") is not True
    assert "secret" not in json.dumps(broker._fixed_operation("audit-record"))
    with pytest.raises(broker.Rejected):
        broker._fixed_operation("arbitrary-command")


def test_peercred_returns_actual_unix_identity():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid, gid = broker._peercred(a)
        assert pid > 0
        import os
        assert uid == os.geteuid()
        assert gid == os.getegid()
    finally:
        a.close()
        b.close()


def test_json_boolean_is_not_a_valid_protocol_version():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        b.sendall(b'{"version":true,"action":"issue"}\n')
        with pytest.raises(broker.Rejected, match="schema unsupported"):
            broker._read_request(a)
    finally:
        a.close()
        b.close()


def test_socket_framing_fails_closed():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        b.sendall(b'{"version":1,"action":"issue"}\n')
        parsed = broker._read_request(a)
        assert parsed["action"] == "issue"
    finally:
        a.close()
        b.close()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        b.sendall(b"x" * (broker.MAX_REQUEST_BYTES + 1))
        with pytest.raises(broker.Rejected):
            broker._read_request(a)
    finally:
        a.close()
        b.close()


def test_prepare_dir_rejects_symlink(tmp_path):
    destination = tmp_path / "dir"
    target = tmp_path / "target"
    target.mkdir()
    destination.symlink_to(target)
    with pytest.raises(broker.Rejected):
        broker.prepare_dir(destination, 0o700, 0)
