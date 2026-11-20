"""Privileged script admission stays opt-in; never runs real sudo in tests."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinelx_core.executor import HandlerError
from sentinelx_core.handlers import build_registry
from sentinelx_core.policy import Policy
from sentinelx_core import privileged_admission as admission


T0 = dt.datetime(2026, 11, 20, 0, 0, tzinfo=dt.timezone.utc)


def _request(**overrides):
    value = {
        "interpreter": "python3",
        "content": "print('bounded')",
        "args": [],
        "cwd": None,
        "env": {},
        "timeout": 60,
        "background": False,
    }
    value.update(overrides)
    return value


def _entry(fingerprint, *, issued=T0, expires=T0 + dt.timedelta(minutes=30)):
    return {
        "fingerprint": fingerprint,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }


def test_exact_approval_and_expiration():
    request = _request()
    fingerprint = admission.request_fingerprint(**request)
    manifest = {"schema": 1, "approvals": [_entry(fingerprint)]}
    assert admission.approved(fingerprint, manifest, now=T0 + dt.timedelta(minutes=1))
    assert not admission.approved(fingerprint, manifest, now=T0 + dt.timedelta(minutes=30))
    assert not admission.approved(fingerprint, manifest, now=T0 - dt.timedelta(seconds=1))


@pytest.mark.parametrize(
    "changes",
    [
        {"content": "print('different')"},
        {"interpreter": "bash"},
        {"args": ["--value"]},
        {"cwd": "/root"},
        {"env": {"SECRET": "value"}},
        {"timeout": 61},
        {"background": True},
    ],
)
def test_fingerprint_binds_all_privileged_request_dimensions(changes):
    baseline = admission.request_fingerprint(**_request())
    changed = admission.request_fingerprint(**_request(**changes))
    assert changed != baseline


def test_canonical_environment_dictionary_order():
    a = admission.request_fingerprint(**_request(env={"A": "1", "B": "2"}))
    b = admission.request_fingerprint(**_request(env={"B": "2", "A": "1"}))
    assert a == b


@pytest.mark.parametrize("problem", ["duplicate", "wildcard", "extra", "duration", "naive", "invalid_schema"])
def test_malformed_manifest_fails_closed(problem):
    fp = admission.request_fingerprint(**_request())
    entry = _entry(fp)
    manifest = {"schema": 1, "approvals": [entry]}
    if problem == "duplicate":
        manifest["approvals"].append(entry.copy())
    elif problem == "wildcard":
        entry["fingerprint"] = "*"
    elif problem == "extra":
        entry["command"] = "/bin/bash"
    elif problem == "duration":
        entry["expires_at"] = (T0 + dt.timedelta(hours=2)).isoformat()
    elif problem == "naive":
        entry["issued_at"] = T0.replace(tzinfo=None).isoformat()
    else:
        manifest["schema"] = 99
    with pytest.raises(admission.AdmissionDenied):
        admission.approved(fp, manifest, now=T0 + dt.timedelta(minutes=1))


def test_mode_deny_without_staging_or_subprocess(monkeypatch, tmp_path):
    p = Policy(script_run_sudo_mode="deny", upload_base=tmp_path)
    handlers = build_registry(policy=p)

    async def run():
        with pytest.raises(HandlerError) as captured:
            await handlers["script_run"](
                {"interpreter": "python3", "content": "print('noop')", "sudo": True}
            )
        assert captured.value.code == "permission_denied"
        assert not list(tmp_path.rglob("script_job_*"))

    import asyncio
    asyncio.run(run())


def test_default_legacy_mode_and_unprivileged_execution(tmp_path):
    assert Policy().script_run_sudo_mode == "legacy"
    p = Policy(script_run_sudo_mode="deny", upload_base=tmp_path)
    handlers = build_registry(policy=p)

    async def run():
        value = await handlers["script_run"](
            {"interpreter": "python3", "content": "print('non-root allowed')", "sudo": False}
        )
        assert value["ok"] is True
        assert "non-root allowed" in value["output"]

    import asyncio
    asyncio.run(run())


def test_approval_mode_missing_manifest_denies(monkeypatch, tmp_path):
    p = Policy(script_run_sudo_mode="approval", upload_base=tmp_path)
    handlers = build_registry(policy=p)
    monkeypatch.setattr(
        admission, "_approval_manifest",
        lambda: (_ for _ in ()).throw(admission.AdmissionDenied("no approval")),
    )

    async def run():
        with pytest.raises(HandlerError) as captured:
            await handlers["script_run"](
                {"interpreter": "bash", "content": "echo test", "sudo": True}
            )
        assert captured.value.code == "permission_denied"
        assert not list(tmp_path.rglob("script_job_*"))

    import asyncio
    asyncio.run(run())


def test_exact_manifest_lookup_is_used(monkeypatch):
    fp = admission.request_fingerprint(**_request())
    manifest = {"schema": 1, "approvals": [_entry(fp)]}
    monkeypatch.setattr(admission, "_approval_manifest", lambda: manifest)
    monkeypatch.setattr(admission.dt, "datetime", FixedDateTime)
    admission.enforce("approval", **_request())
    with pytest.raises(admission.AdmissionDenied):
        admission.enforce("approval", **_request(content="print('unapproved')"))


class FixedDateTime(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return T0 + dt.timedelta(minutes=1)


def test_config_parsing_rejects_unknown_or_malformed_mode():
    for mode in ("legacy", "deny", "approval"):
        assert Policy.from_dict({"security": {"script_run_sudo_mode": mode}}).script_run_sudo_mode == mode
    for mode in ("allow", "", None, 1):
        with pytest.raises(ValueError):
            Policy.from_dict({"security": {"script_run_sudo_mode": mode}})


def test_approval_file_identity_rejects_symlink(monkeypatch, tmp_path):
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"schema": 1, "approvals": []}))
    symlink = tmp_path / "approvals.json"
    symlink.symlink_to(target)
    monkeypatch.setattr(admission, "APPROVAL_PATH", symlink)
    original_lstat = Path.lstat

    def root_owned_parent(self):
        stat_result = original_lstat(self)
        if self == tmp_path:
            return SimpleNamespace(st_mode=stat_result.st_mode, st_uid=0)
        return stat_result

    monkeypatch.setattr(Path, "lstat", root_owned_parent)
    with pytest.raises(admission.AdmissionDenied, match="unavailable"):
        admission._approval_manifest()


def test_approval_file_identity_rejects_non_root_file(monkeypatch, tmp_path):
    approval = tmp_path / "approvals.json"
    approval.write_text(json.dumps({"schema": 1, "approvals": []}))
    monkeypatch.setattr(admission, "APPROVAL_PATH", approval)
    original_lstat = Path.lstat

    def root_owned_parent(self):
        stat_result = original_lstat(self)
        if self == tmp_path:
            return SimpleNamespace(st_mode=stat_result.st_mode, st_uid=0)
        return stat_result

    monkeypatch.setattr(Path, "lstat", root_owned_parent)
    with pytest.raises(admission.AdmissionDenied, match="untrusted"):
        admission._approval_manifest()


def test_no_request_content_echoed_in_denial(monkeypatch):
    secret = "SENSITIVE_SECRET_SHOULD_NOT_APPEAR"
    with pytest.raises(admission.AdmissionDenied) as captured:
        admission.enforce("deny", **_request(content=secret))
    assert secret not in str(captured.value)
