"""Local API adapter for the root broker: no cloud protocol extension needed.

This uses a simulated Unix socket in tests; no root daemon is started.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from security import privileged_broker as broker
from sentinelx_core import local_audit
from sentinelx_core.executor import Executor
from sentinelx_protocol import RequestMessage


def _envelope(ticket: str, operation: str = "audit-check") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "sentinel-local-api-check123",
        "method": {
            "audit-check": "tohy.audit.check",
            "audit-record": "tohy.audit.record",
        }[operation],
        "params": {"ticket": ticket},
    }


def test_strict_jsonrpc_translation():
    token = "c" * 64
    request_id, native = broker._jsonrpc_to_native(_envelope(token))
    assert request_id == "sentinel-local-api-check123"
    assert native == {
        "version": 1, "action": "execute",
        "operation": "audit-check", "ticket": token,
    }


@pytest.mark.parametrize(
    "update",
    [
        {"method": "tohy.audit.issue"},
        {"method": "tohy.audit.execute"},
        {"method": "system.run"},
        {"id": True},
        {"id": "x" * 65},
        {"jsonrpc": "1.0"},
        {"params": {"operation": "audit-check"}},
        {"params": {"ticket": "a" * 64, "argv": ["/bin/bash"]}},
        {"params": {"ticket": "A" * 64}},
        {"params": {"operation": "audit-record", "ticket": "a" * 64}},
        {"extra": "unexpected"},
    ],
)
def test_jsonrpc_rejects_unapproved_methods_and_parameters(update):
    packet = _envelope("a" * 64)
    packet.update(update)
    with pytest.raises(broker.Rejected):
        broker._jsonrpc_to_native(packet)


def test_jsonrpc_method_binds_operation_irrespective_of_parameters():
    ticket = "b" * 64
    request_id, native = broker._jsonrpc_to_native(_envelope(ticket, "audit-record"))
    assert request_id
    assert native["operation"] == "audit-record"
    assert "operation" not in _envelope(ticket, "audit-record")["params"]


def test_local_api_audit_redacts_ticket_and_preserves_other_fields(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    token = "SENSITIVE_TICKET_" + "d" * 64
    monkeypatch.setattr(local_audit, "AUDIT_PATH", path)
    local_audit._reset_retention_state()
    try:
        before = {
            "operation": "call", "endpoint": "tohy_privileged_broker",
            "action": "audit.check", "params": {
                "operation": "audit-check", "ticket": token, "reason": "diagnostic"
            }
        }
        local_audit.record("local_api", before, ok=True)
        assert before["params"]["ticket"] == token
        saved = path.read_text()
        assert token not in saved
        row = json.loads(saved)
        assert row["payload"]["params"] == {"omitted": "privileged_request"}
        assert row["payload"]["endpoint"] == "tohy_privileged_broker"
        assert row["payload"]["action"] == "audit.check"
        assert "diagnostic" not in saved
    finally:
        local_audit._reset_retention_state()


def test_other_local_api_audit_remains_unchanged(tmp_path, monkeypatch):
    p = tmp_path / "audit.jsonl"
    monkeypatch.setattr(local_audit, "AUDIT_PATH", p)
    local_audit._reset_retention_state()
    try:
        local_audit.record("local_api", {"operation": "list", "endpoint": "docker"}, ok=True)
        row = json.loads(p.read_text())
        assert row["payload"] == {"operation": "list", "endpoint": "docker"}
    finally:
        local_audit._reset_retention_state()


def test_socket_local_api_end_to_end_through_executor(tmp_path, monkeypatch):
    async def scenario():
        socket_file = tmp_path / "local-broker.sock"
        database = tmp_path / "tickets.sqlite3"
        monkeypatch.setattr(broker, "_trusted_parent", lambda _: None)
        store = broker.TicketStore(database)
        b = broker.Broker.__new__(broker.Broker)
        b.store = store
        seen = []

        async def accept(reader, writer):
            try:
                obj = json.loads(await reader.readline())
                seen.append(obj["method"])
                rpc_id, native = broker._jsonrpc_to_native(obj)
                assert native["operation"] == "audit-check"
                # This is NOT a peer credential test: simulated service identity.
                assert store.consume(
                    native["ticket"], "audit-check", broker.AGENT_UID, broker.AGENT_GID
                )
                response = {
                    "jsonrpc": "2.0", "id": rpc_id,
                    "result": {
                        "ok": True, "operation": "audit-check", "completed": True
                    },
                }
                writer.write((json.dumps(response) + "\n").encode())
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
                "      audit.check:\n"
                "        method: tohy.audit.check\n"
            )
            ticket = store.issue("audit-check", broker.AGENT_UID, broker.AGENT_GID, 60)
            audit_path = tmp_path / "audit.jsonl"
            monkeypatch.setattr(local_audit, "AUDIT_PATH", audit_path)
            local_audit._reset_retention_state()
            try:
                executor = Executor(config_path=config)
                assert "local_api" in executor.capability_names()
                response = await executor.dispatch(
                    RequestMessage(
                        id="local-api-broker-e2e", op="local_api",
                        payload={
                            "operation": "call",
                            "endpoint": "tohy_privileged_broker",
                            "action": "audit.check",
                            "params": {
                                "ticket": ticket,
                            },
                        },
                    )
                )
                assert response["ok"] is True, response
                assert response["result"]["result"]["completed"] is True
                assert seen == ["tohy.audit.check"]
                saved = audit_path.read_text()
                assert ticket not in saved
                assert '"omitted"' in saved
                # A second attempt cannot succeed because the same ticket was consumed.
                assert not store.consume(
                    ticket, "audit-check", broker.AGENT_UID, broker.AGENT_GID
                )
            finally:
                local_audit._reset_retention_state()
        finally:
            server.close()
            await server.wait_closed()
            store.db.close()

    asyncio.run(scenario())
