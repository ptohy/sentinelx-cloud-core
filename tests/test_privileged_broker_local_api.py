"""Secretless privileged audit status via the existing SentinelX local_api.

No root service, sudoers modification, production socket or real privileged
effect is required by this suite.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from security import privileged_broker as broker
from sentinelx_core import local_audit
from sentinelx_core.executor import Executor
from sentinelx_protocol import RequestMessage


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setattr(broker, "_trusted_parent", lambda _: None)
    value = broker.TicketStore(tmp_path / "root-operations.sqlite3")
    yield value
    value.db.close()


def _rpc(method="tohy.audit.status", params=None):
    return {
        "jsonrpc": "2.0",
        "id": "sentinel-audit-status-1",
        "method": method,
        "params": {} if params is None else params,
    }


def test_status_method_never_carries_ticket():
    request_id, native = broker._jsonrpc_to_native(_rpc())
    assert request_id == "sentinel-audit-status-1"
    assert native == {"version": 1, "action": "status"}


@pytest.mark.parametrize(
    "change",
    [
        {"method": "tohy.audit.issue"},
        {"method": "tohy.audit.check"},
        {"method": "tohy.audit.record"},
        {"method": "tohy.audit.execute"},
        {"method": "system.run"},
        {"id": True},
        {"id": "x" * 65},
        {"jsonrpc": "1.0"},
        {"params": {"ticket": "a" * 64}},
        {"params": {"operation": "audit-check"}},
        {"params": {"argv": ["/bin/bash"]}},
        {"params": {"ticket": "a" * 64, "operation": "audit-record"}},
        {"extra": "unexpected"},
    ],
)
def test_jsonrpc_rejects_execution_and_all_arguments(change):
    packet = _rpc()
    packet.update(change)
    with pytest.raises(broker.Rejected):
        broker._jsonrpc_to_native(packet)


def test_root_initiated_fixed_operation_is_idempotent(store, monkeypatch):
    effect = []
    monkeypatch.setattr(broker, "_fixed_operation", lambda op: effect.append(op) or {"ok": True})
    request_id = "a" * 32
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    result = b.handle(
        {"version": 1, "action": "run", "operation": "audit-check", "request_id": request_id},
        0, 0,
    )
    assert result == {
        "ok": True, "operation": "audit-check", "completed": True, "request_id": request_id
    }
    with pytest.raises(broker.Rejected, match="already submitted"):
        b.handle(
            {"version": 1, "action": "run", "operation": "audit-check", "request_id": request_id},
            0, 0,
        )
    assert effect == ["audit-check"]
    receipt = b.handle({"version": 1, "action": "status"}, broker.AGENT_UID, broker.AGENT_GID)
    assert receipt["read_only"] is True
    assert receipt["entries"][0]["status"] == "completed"
    assert receipt["entries"][0]["operation"] == "audit-check"
    assert receipt["entries"][0]["request_id"] == request_id
    assert "ticket" not in json.dumps(receipt)


@pytest.mark.parametrize(
    "request_id,operation",
    [
        ("", "audit-check"),
        ("z" * 32, "audit-check"),
        ("a" * 31, "audit-check"),
        ("A" * 32, "audit-check"),
        ("b" * 32, "shell"),
        ("b" * 32, "systemctl restart ssh"),
    ],
)
def test_root_host_run_rejects_bad_id_or_operation(store, request_id, operation):
    with pytest.raises(broker.Rejected):
        store.run_host_operation(request_id, operation)


def test_only_root_can_start_operation(store, monkeypatch):
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    calls = []
    monkeypatch.setattr(broker, "_fixed_operation", lambda op: calls.append(op))
    payload = {"version": 1, "action": "run", "operation": "audit-check", "request_id": "a" * 32}
    with pytest.raises(broker.Rejected, match="root identity"):
        b.handle(payload, broker.AGENT_UID, broker.AGENT_GID)
    with pytest.raises(broker.Rejected, match="fields invalid"):
        b.handle({**payload, "sudo": True}, 0, 0)
    assert calls == []


def test_only_service_identity_can_read_status(store):
    b = broker.Broker.__new__(broker.Broker)
    b.store = store
    with pytest.raises(broker.Rejected, match="reader identity"):
        b.handle({"version": 1, "action": "status"}, 1000, 1000)
    with pytest.raises(broker.Rejected, match="fields invalid"):
        b.handle({"version": 1, "action": "status", "ticket": "any"}, broker.AGENT_UID, broker.AGENT_GID)
    assert b.handle({"version": 1, "action": "status"}, broker.AGENT_UID, broker.AGENT_GID)["read_only"]


def test_failed_effect_never_retries(store, monkeypatch):
    runs = []
    def fail(op):
        runs.append(op)
        raise broker.Rejected("synthetic operation failure")
    monkeypatch.setattr(broker, "_fixed_operation", fail)
    with pytest.raises(broker.Rejected, match="failed"):
        store.run_host_operation("b" * 32, "audit-record")
    with pytest.raises(broker.Rejected, match="already submitted"):
        store.run_host_operation("b" * 32, "audit-record")
    assert runs == ["audit-record"]
    assert store.recent_host_operations()["entries"][0]["status"] == "failed"


def test_unconfirmed_start_is_never_reported_as_completed(store):
    store.db.execute(
        "INSERT INTO host_operations VALUES (?, ?, ?, ?, NULL, 'started_unknown')",
        ("c" * 32, "audit-check", store.boot_id, 100),
    )
    latest = store.recent_host_operations()["entries"][0]
    assert latest["status"] == "started_unknown"
    store.boot_id = "00000000-0000-0000-0000-000000000000"
    after_restart = store.recent_host_operations()["entries"][0]
    assert after_restart["status"] == "unconfirmed_after_restart"


def test_receipt_status_is_bounded_to_ten(store, monkeypatch):
    monkeypatch.setattr(broker, "_fixed_operation", lambda _: {"ok": True})
    for i in range(13):
        store.run_host_operation(f"{i:032x}", "audit-check")
    receipts = store.recent_host_operations()
    assert len(receipts["entries"]) == 10
    assert all(row["operation"] == "audit-check" for row in receipts["entries"])


def test_audit_of_status_carries_no_privileged_secrets(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", path)
    local_audit._reset_retention_state()
    try:
        marker = "SENSITIVE_DO_NOT_PERSIST"
        payload = {
            "operation": "call", "endpoint": "tohy_privileged_broker",
            "action": "audit.status", "params": {"ticket": marker, "unexpected": marker}
        }
        local_audit.record("local_api", payload, ok=False, error="synthetic-denial")
        text = path.read_text()
        assert marker not in text
        row = json.loads(text)
        assert row["payload"]["params"] == {"omitted": "privileged_request"}
        assert row["payload"]["action"] == "invalid"
    finally:
        local_audit._reset_retention_state()


def test_unrelated_local_api_audit_is_preserved(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", path)
    local_audit._reset_retention_state()
    try:
        payload = {"operation": "list", "endpoint": "docker"}
        local_audit.record("local_api", payload, ok=True)
        assert json.loads(path.read_text())["payload"] == payload
    finally:
        local_audit._reset_retention_state()


def test_agent_dispatches_read_only_status_without_ticket(tmp_path, monkeypatch, store):
    async def run_scenario():
        socket_file = tmp_path / "fake-broker.sock"
        b = broker.Broker.__new__(broker.Broker)
        b.store = store
        methods = []

        async def accept(reader, writer):
            try:
                request = json.loads(await reader.readline())
                methods.append(request.get("method"))
                request_id, native = broker._jsonrpc_to_native(request)
                assert native == {"version": 1, "action": "status"}
                receipt = b.handle(native, broker.AGENT_UID, broker.AGENT_GID)
                writer.write(
                    (json.dumps({"jsonrpc": "2.0", "id": request_id, "result": receipt}) + "\n").encode()
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(accept, path=str(socket_file))
        try:
            config = tmp_path / "config.yaml"
            config.write_text(
                "local_apis:\n"
                "  tohy_privileged_broker:\n"
                "    transport: unix\n"
                f"    path: {socket_file}\n"
                "    protocol: jsonrpc\n"
                "    timeout_s: 5\n"
                "    actions:\n"
                "      audit.status:\n"
                "        method: tohy.audit.status\n"
            )
            audit_path = tmp_path / "audit.jsonl"
            monkeypatch.setattr(local_audit, "AUDIT_PATH", audit_path)
            local_audit._reset_retention_state()
            executor = Executor(config_path=config)
            assert "local_api" in executor.capability_names()
            response = await executor.dispatch(
                RequestMessage(
                    id="read-only-status",
                    op="local_api",
                    payload={
                        "operation": "call",
                        "endpoint": "tohy_privileged_broker",
                        "action": "audit.status",
                        "params": {},
                    },
                )
            )
            assert response["ok"], response
            assert response["result"]["result"] == {
                "ok": True, "read_only": True, "entries": [],
            }
            assert methods == ["tohy.audit.status"]
            audit = json.loads(audit_path.read_text())
            assert audit["payload"]["params"] == {"omitted": "privileged_request"}
            assert "ticket" not in json.dumps(response)
            local_audit._reset_retention_state()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_scenario())
