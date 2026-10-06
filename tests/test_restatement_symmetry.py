"""One restatement, three doors: REST, CLI, and LedgerClient.

AGENTS.md requires every write operation to work identically through all three
entry points. The integrity rules (verified human author, ticket, freshness,
monotonic chain) and the metadata effect live in one handler, so no door has
weaker integrity. Authorization is the exception, by design: the admin list is
enforced only at the REST boundary, because a CLI or SDK caller owns its own
environment and could grant itself. Those doors record the actor instead.

Storage coverage lives alongside: the same restatement is driven through the
file backend, SQLite, and (when configured) PostgreSQL, because the append-only
guarantee a restatement depends on is enforced at different layers in each.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from conftest import LAYER_ID, auth_header, canonical_shell
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from storage_db import owner_of, prepare_storage
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends import create_backend
from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB, BACKEND_TYPE_FILE
from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.backends.errors import LayerConflictError
from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.integrity import Severity, verify_merkle_integrity
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.cli.main import main
from traust_ledger.config import ServiceConfig
from traust_ledger.handlers.restatement_handler import apply_restatement
from traust_ledger.paths import layer_file_path

ADMIN = "admin@example.com"
OUTSIDER = "dev@example.com"
RATIONALE = "Baseline report reissued after the v1->v2 fingerprint re-stamp."
BEFORE = {"FIND-1": "a" * 64}
AFTER = {"FIND-1": "b" * 64}


def _block() -> dict:
    return {
        "target": "claim_hashes",
        "reason": "baseline_rewrite",
        "before": BEFORE,
        "after": AFTER,
        "authority": {"ticket": "SEC-1234"},
    }


def _shell_with_claims() -> dict:
    shell = canonical_shell()
    shell["metadata"]["claim_hashes"] = dict(BEFORE)
    return shell


def _admin_actor(identity: str = ADMIN) -> LayerActor:
    return LayerActor(kind="human", identity=identity, identity_verified=True)


# ── REST ─────────────────────────────────────────────────────────────────────


@pytest.fixture()
def admin_client(app_with_backend, tmp_path: Path) -> TestClient:
    app_with_backend.state.config = app_with_backend.state.config.model_copy(
        update={"admin_identities": [ADMIN]}
    )
    FileBackend().store(tmp_path / f"{LAYER_ID}.json", _shell_with_claims())
    return TestClient(app_with_backend)


class TestRest:
    def test_admin_restatement_accepted(self, admin_client: TestClient, tmp_path: Path) -> None:
        response = admin_client.post(
            f"/v1/ledger/layers/{LAYER_ID}/restate",
            json={"restatement": _block(), "rationale": RATIONALE},
            headers=auth_header(identity=ADMIN),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["target"] == "claim_hashes"
        assert body["merkle_root"]

        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["metadata"]["claim_hashes"] == AFTER
        assert layer["events"][0]["restatement"]["before"] == BEFORE

    def test_non_admin_gets_403_not_401(self, admin_client: TestClient) -> None:
        """403, deliberately. A 401 tells a caller with a perfectly valid token
        to re-authenticate, sending them round a loop that cannot succeed."""
        response = admin_client.post(
            f"/v1/ledger/layers/{LAYER_ID}/restate",
            json={"restatement": _block(), "rationale": RATIONALE},
            headers=auth_header(identity=OUTSIDER),
        )
        assert response.status_code == 403
        assert "not a ledger administrator" in response.json()["detail"]

    def test_unauthenticated_gets_401(self, admin_client: TestClient) -> None:
        response = admin_client.post(
            f"/v1/ledger/layers/{LAYER_ID}/restate",
            json={"restatement": _block(), "rationale": RATIONALE},
        )
        assert response.status_code == 401

    def test_stale_before_is_refused(self, admin_client: TestClient) -> None:
        block = _block() | {"before": {"FIND-1": "9" * 64}}
        response = admin_client.post(
            f"/v1/ledger/layers/{LAYER_ID}/restate",
            json={"restatement": block, "rationale": RATIONALE},
            headers=auth_header(identity=ADMIN),
        )
        assert response.status_code == 422
        assert "does not match the stored value" in response.json()["detail"]

    def test_missing_ticket_is_refused(self, admin_client: TestClient) -> None:
        block = _block()
        del block["authority"]
        response = admin_client.post(
            f"/v1/ledger/layers/{LAYER_ID}/restate",
            json={"restatement": block, "rationale": RATIONALE},
            headers=auth_header(identity=ADMIN),
        )
        assert response.status_code == 422

    def test_route_is_in_the_openapi_spec(self, admin_client: TestClient) -> None:
        spec = admin_client.app.openapi()
        path = spec["paths"]["/v1/ledger/layers/{layer_id}/restate"]["post"]
        assert set(path["responses"]) >= {"200", "401", "403", "422"}


# ── CLI ──────────────────────────────────────────────────────────────────────


class TestCli:
    def _prepare(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: str) -> None:
        FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", _shell_with_claims())
        monkeypatch.setenv("LAAS_BACKEND_TYPE", BACKEND_TYPE_FILE)
        monkeypatch.setenv("LAAS_DATA_DIR", str(tmp_path))
        monkeypatch.setattr("traust_ledger.cli.commands.restate.require_cli_auth", lambda: False)
        monkeypatch.setattr(
            "traust_ledger.cli.commands.restate.require_verified_actor",
            lambda: _admin_actor(identity),
        )

    def _argv(self, tmp_path: Path, **over) -> list[str]:
        after = tmp_path / "after.json"
        after.write_text(json.dumps(AFTER), encoding="utf-8")
        argv = [
            "restate",
            "--layer",
            LAYER_ID,
            "--target",
            "claim_hashes",
            "--reason",
            "baseline_rewrite",
            "--before",
            json.dumps(BEFORE),
            "--after",
            f"@{after}",
            "--ticket",
            "SEC-1234",
            "--rationale",
            RATIONALE,
        ]
        for flag, value in over.items():
            argv += [f"--{flag.replace('_', '-')}", value]
        return argv

    def test_admin_restatement_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        self._prepare(tmp_path, monkeypatch, ADMIN)
        assert main(self._argv(tmp_path)) == 0
        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["metadata"]["claim_hashes"] == AFTER
        assert json.loads(capsys.readouterr().out)["target"] == "claim_hashes"

    def test_cli_does_not_authorize_and_records_the_actor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An admin list the caller sets for itself is not authorization, so the
        CLI ignores it and records who restated."""
        self._prepare(tmp_path, monkeypatch, OUTSIDER)
        monkeypatch.setenv("LAAS_ADMIN_IDENTITIES", ADMIN)
        assert main(self._argv(tmp_path)) == 0
        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["metadata"]["claim_hashes"] == AFTER
        assert layer["events"][0]["source"]["actor"]["identity"] == OUTSIDER

    def test_at_file_and_inline_json_agree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A claim-hash table runs to thousands of entries; `@file` exists so
        the ledger's authority does not depend on shell quoting."""
        from traust_ledger.cli.commands.restate import _load_json_arg

        path = tmp_path / "value.json"
        path.write_text(json.dumps(AFTER), encoding="utf-8")
        assert _load_json_arg(f"@{path}") == _load_json_arg(json.dumps(AFTER))

    def test_cli_config_ignores_authorization_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from traust_ledger.cli import config_from_env

        monkeypatch.setenv("LAAS_ADMIN_IDENTITIES", "a@x.com")
        monkeypatch.setenv("LAAS_RESTATEMENT_MIN_APPROVERS", "2")
        config = config_from_env()
        assert config.admin_identities == []
        assert config.restatement_min_approvers == 0


# ── LedgerClient ─────────────────────────────────────────────────────────────


class _AdminVerifier:
    def __init__(self, identity: str = ADMIN) -> None:
        self._identity = identity

    def verify(self, token: str) -> LayerActor:
        return LayerActor(kind="human", identity=self._identity, identity_verified=True)


def _client(tmp_path: Path, identity: str = ADMIN):
    from traust_ledger._internal.integrity.signing import SigningConfig
    from traust_ledger.client import LedgerClient

    FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", _shell_with_claims())
    client = LedgerClient(
        token="stub",
        verifier=_AdminVerifier(identity),
        data_dir=str(tmp_path),
        signing_config=SigningConfig(method="none"),
    )
    return client


class TestLedgerClient:
    def test_correct_applies(self, tmp_path: Path) -> None:
        result = _client(tmp_path).restate(LAYER_ID, _block(), rationale=RATIONALE)
        assert result["target"] == "claim_hashes"
        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["metadata"]["claim_hashes"] == AFTER

    def test_sdk_does_not_authorize_and_records_the_actor(self, tmp_path: Path) -> None:
        _client(tmp_path, OUTSIDER).restate(LAYER_ID, _block(), rationale=RATIONALE)
        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["events"][0]["source"]["actor"]["identity"] == OUTSIDER

    def test_machine_actor_is_refused(self, tmp_path: Path) -> None:
        """A service-account token maps to a machine actor; a restatement is a
        human decision, so it is refused on every door."""
        from traust_ledger._internal.integrity.signing import SigningConfig
        from traust_ledger.client import LedgerClient, LedgerError

        class _MachineVerifier:
            def verify(self, token: str) -> LayerActor:
                return LayerActor(kind="machine", identity="sci/pod", identity_verified=True)

        FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", _shell_with_claims())
        client = LedgerClient(
            token="stub",
            verifier=_MachineVerifier(),
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
        )
        with pytest.raises(LedgerError):
            client.restate(LAYER_ID, _block(), rationale=RATIONALE)
        layer = FileBackend().load(tmp_path / f"{LAYER_ID}.json")
        assert layer["events"] == []


# ── Storage backends ─────────────────────────────────────────────────────────


def _exercise_restatement(backend, data_dir: Path, layer_id: str) -> dict:
    """Drive one restatement through a backend and return the reloaded layer."""
    path = layer_file_path(str(data_dir), layer_id)
    backend.initialize(path, _shell_with_claims(), owner_of(backend))
    writer = LedgerWriter(backend=backend)
    config = ServiceConfig(data_dir=str(data_dir))
    apply_restatement(
        layer_id,
        _block(),
        RATIONALE,
        _admin_actor(),
        "2026-09-25T12:00:00+00:00",
        writer,
        config,
    )
    return backend.load(path)


@pytest.mark.parametrize("backend_type", [BACKEND_TYPE_FILE, BACKEND_TYPE_DB])
def test_restatement_lifecycle_file_and_sqlite(backend_type: str, tmp_path: Path) -> None:
    data_dir = tmp_path / "layers"
    if backend_type == BACKEND_TYPE_DB:
        prepare_storage(f"sqlite:///{tmp_path / 'ledger.db'}")
    backend = create_backend(
        backend_type,
        data_dir=data_dir,
        database_url=f"sqlite:///{tmp_path / 'ledger.db'}",
    )
    layer = _exercise_restatement(backend, data_dir, "correct-e2e")

    assert layer["metadata"]["claim_hashes"] == AFTER
    (event,) = layer["events"]
    assert event["source"]["type"] == "restatement"
    assert event["restatement"]["before"] == BEFORE
    assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    # Reopening proves the block survived serialization, which for the DB
    # backend means the event payload round-tripped through BYTEA.
    reopened = create_backend(
        backend_type,
        data_dir=data_dir,
        database_url=f"sqlite:///{tmp_path / 'ledger.db'}",
    ).load(layer_file_path(str(data_dir), "correct-e2e"))
    assert reopened == layer


def test_sqlite_refuses_to_drop_a_restatement_event(tmp_path: Path) -> None:
    """Append-only is what makes a restatement evidence rather than a claim."""
    data_dir = tmp_path / "layers"
    engine = create_engine(f"sqlite:///{tmp_path / 'ledger.db'}")
    prepare_storage(engine)
    DbBackend.create_tables(engine)
    backend = DbBackend(engine)
    layer = _exercise_restatement(backend, data_dir, "correct-append-only")

    with pytest.raises(LayerConflictError, match="cannot remove"):
        backend.store(
            layer_file_path(str(data_dir), "correct-append-only"), {**layer, "events": []}
        )

    tampered = json.loads(json.dumps(layer))
    tampered["events"][0]["restatement"]["before"] = {"FIND-1": "0" * 64}
    with pytest.raises(LayerConflictError, match="cannot rewrite"):
        backend.store(layer_file_path(str(data_dir), "correct-append-only"), tampered)


@pytest.mark.integration
def test_postgresql_restatement_lifecycle(tmp_path: Path) -> None:
    url = os.environ.get("LEDGER_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LEDGER_TEST_DATABASE_URL is not configured")
    layer_id = f"correct-e2e-{uuid.uuid4().hex}"
    backend = create_backend(BACKEND_TYPE_DB, database_url=url)
    layer = _exercise_restatement(backend, tmp_path, layer_id)

    assert layer["metadata"]["claim_hashes"] == AFTER
    assert layer["events"][0]["restatement"]["authority"]["ticket"] == "SEC-1234"
    assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    path = layer_file_path(str(tmp_path), layer_id)
    with pytest.raises(LayerConflictError, match="cannot remove"):
        backend.store(path, {**layer, "events": []})

    # PostgreSQL enforces the same rule a second time in the DDL: the
    # contracts-shipped trigger rejects UPDATE/DELETE on events outright, so
    # even a caller bypassing the Python guard cannot unwind a restatement.
    reopened = create_backend(BACKEND_TYPE_DB, database_url=url).load(path)
    assert reopened == layer
