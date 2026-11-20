"""Opt-in SentinelX client for the root-owned fixed-operation broker.

These tests use no installed broker and never grant system privileges.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from sentinelx_core import local_audit
from sentinelx_core.executor import Executor, HandlerError
from sentinelx_protocol import RequestMessage
from sentinelx_core.handlers import build_registry
from sentinelx_core.handlers import privileged_broker as client
from sentinelx_core.policy import Policy


def test_broker_operation_absent_by_default():
    assert Policy().privileged_broker_enabled is False
    assert "privileged_broker" not in build_registry(policy=Policy())


def test_broker_operation_explicitly_enabled():
    policy = Policy.from_dict({"security": {"privileged_broker_enabled": True}})
    assert policy.privileged_broker_enabled is True
    assert "privileged_broker" in build_registry(policy=policy)


@pytest.mark.parametrize("invalid", ["true", "", None, 1, [], {}, "False"])
def test_invalid_broker_toggle_fails_configuration(invalid):
    with pytest.raises(ValueError, match="must be a boolean"):
        Policy.from_dict({"security": {"privileged_broker_enabled": invalid}})


def test_broker_disabled_ops_takes_precedence():
    p = Policy(privileged_broker_enabled=True, disabled_ops=frozenset({"privileged_broker"}))
    assert "privileged_broker" not in build_registry(policy=p)


def test_valid_request_calls_fixed_transport_only(monkeypatch):
    operations = []
    ticket = "a" * 64

    def fake_send(operation, token):
        operations.append((operation, token))
        return {"ok": True, "operation": operation, "completed": True}

    monkeypatch.setattr(client, "_send", fake_send)
    handle = client.make_privileged_broker_handler()
    result = asyncio.run(handle({"operation": "audit-check", "ticket": ticket}))
    assert result == {"ok": True, "operation": "audit-check", "completed": True}
    assert operations == [("audit-check", ticket)]


@pytest.mark.parametrize(
    "payload",
    [
        {"operation": "audit-check"},
        {"operation": "audit-check", "ticket": "a" * 64, "argv": ["/bin/bash"]},
        {"operation": "delete-all", "ticket": "a" * 64},
        {"operation": "audit-check", "ticket": "not-a-token"},
        {"operation": "audit-record", "ticket": "A" * 64},
        {"operation": "audit-record", "ticket": 5},
        {"operation": "audit-record", "ticket": "b" * 64, "sudo": True},
        [],
        "command",
    ],
)
def test_invalid_requests_never_connect(monkeypatch, payload):
    seen = []
    monkeypatch.setattr(client, "_send", lambda *args: seen.append(args))
    handler = client.make_privileged_broker_handler()
    with pytest.raises(HandlerError) as err:
        asyncio.run(handler(payload))
    assert err.value.code == "permission_denied"
    assert seen == []


def test_socket_missing_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(client, "SOCKET", tmp_path / "absent" / "broker.sock")
    monkeypatch.setattr(client.sys, "platform", "linux")
    monkeypatch.setattr(client.os, "uname", lambda: type("Uname", (), {"nodename": "codex-dev"})())
    monkeypatch.setattr(client.os, "geteuid", lambda: 992)
    monkeypatch.setattr(client.os, "getegid", lambda: 990)
    with pytest.raises(HandlerError, match="socket unavailable"):
        client._send("audit-check", "f" * 64)


def test_socket_untrusted_identity_rejected(monkeypatch, tmp_path):
    folder = tmp_path / "broker"
    folder.mkdir()
    fake_socket = folder / "broker.sock"
    fake_socket.write_text("not actually a socket")
    monkeypatch.setattr(client, "SOCKET", fake_socket)
    monkeypatch.setattr(client.sys, "platform", "linux")
    monkeypatch.setattr(client.os, "uname", lambda: type("Uname", (), {"nodename": "codex-dev"})())
    monkeypatch.setattr(client.os, "geteuid", lambda: 992)
    monkeypatch.setattr(client.os, "getegid", lambda: 990)
    with pytest.raises(HandlerError, match="socket identity"):
        client._send("audit-check", "b" * 64)


def test_audit_logs_never_include_bearer_ticket(tmp_path, monkeypatch):
    ticket = "SECRET_BROKER_TICKET_" + "c" * 64
    leaked = "SECRET_EXTRA_FIELD"
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", path)
    local_audit._reset_retention_state()
    try:
        for ok in (True, False):
            local_audit.record(
                "privileged_broker",
                {"operation": "audit-check", "ticket": ticket, "arbitrary": leaked},
                ok=ok,
                error="privileged broker rejected request" if not ok else None,
            )
        serialized = path.read_text()
        assert ticket not in serialized
        assert leaked not in serialized
        assert "SECRET_BROKER_TICKET" not in serialized
        rows = [json.loads(line) for line in serialized.splitlines()]
        assert len(rows) == 2
        assert all(row["payload"] == {
            "operation": "audit-check", "bearer_ticket": "omitted",
        } for row in rows)
    finally:
        local_audit._reset_retention_state()


def test_audit_redacts_invalid_operation_and_payload(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", path)
    local_audit._reset_retention_state()
    local_audit.record("privileged_broker", {
        "operation": "BAD_SECRET_VALUE", "ticket": "secret",
    }, ok=False)
    text = path.read_text()
    assert "BAD_SECRET_VALUE" not in text
    assert '"invalid"' in text
    local_audit._reset_retention_state()


def test_wire_request_dispatches_only_when_broker_enabled(monkeypatch, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("security:\n  privileged_broker_enabled: true\n")
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", audit_path)
    local_audit._reset_retention_state()
    ticket = "e" * 64
    calls = []

    def fake_send(operation, secret):
        calls.append((operation, secret))
        return {"ok": True, "operation": operation, "completed": True}

    monkeypatch.setattr(client, "_send", fake_send)
    executor = Executor(config_path=config)
    request = RequestMessage(
        id="broker-protocol-1",
        op="privileged_broker",
        payload={"operation": "audit-check", "ticket": ticket},
    )
    response = asyncio.run(executor.dispatch(request))
    assert response["ok"] is True
    assert response["result"]["completed"] is True
    assert calls == [("audit-check", ticket)]
    assert ticket not in audit_path.read_text()
    assert '"omitted"' in audit_path.read_text()


def test_wire_request_is_unsupported_when_host_not_opted_in(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("security:\n  privileged_broker_enabled: false\n")
    executor = Executor(config_path=config)
    request = RequestMessage(
        id="broker-protocol-disabled",
        op="privileged_broker",
        payload={"operation": "audit-check", "ticket": "f" * 64},
    )
    response = asyncio.run(executor.dispatch(request))
    assert response["ok"] is False
    assert response["error"]["code"] == "unsupported_op"
