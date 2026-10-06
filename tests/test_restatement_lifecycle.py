"""One layer, walked end to end through restatement, on every backend.

The unit tests check each rule in isolation. This walks the SEQUENCE, because
that is where the rules actually bite: whether a field has a prior value, how
many events precede the restatement, and what the chain terminates at are all
properties of history, not of a single call.

Fixture: ``tests/fixtures/restatement-lifecycle.json``.

Stages
  1. empty shell            — restating anything is refused; there is nothing to restate
  2. baseline written       — ordinary write path, no ticket, no admin
  3. first restatement      — immediately after baselining, one event in the layer
  4. determinations appended— three ordinary events, then a second restatement
  5. sibling repaired       — a file beside the layer changes: artifact_digests moves
  6. failure modes          — each refusal leaves the layer byte-identical
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from storage_db import owner_of, prepare_storage
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends import create_backend
from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB, BACKEND_TYPE_FILE
from traust_ledger._internal.integrity import Severity, verify_merkle_integrity
from traust_ledger._internal.restatements import is_restatement, restatements_for, terminal_value
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.api.findings import resolve_layer_findings
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import (
    NotAnAdminError,
    NothingToRestateError,
    RestatementAuthorityError,
    ServiceError,
    StaleRestatementError,
)
from traust_ledger.handlers.restatement_handler import apply_restatement
from traust_ledger.paths import layer_file_path
from traust_ledger.service.auth import authorize_restatement

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "restatement-lifecycle.json").read_text()
)
LAYER_ID = FIXTURE["layer_id"]
ADMIN = LayerActor(kind="human", identity=FIXTURE["admin"], identity_verified=True)
OUTSIDER = LayerActor(kind="human", identity=FIXTURE["outsider"], identity_verified=True)
NOW = "2026-09-10T12:00:00+00:00"


class Harness:
    """A layer under test on one backend, plus the calls a stage needs."""

    def __init__(self, backend, data_dir: Path, layer_id: str) -> None:
        self.backend = backend
        self.writer = LedgerWriter(backend=backend)
        self.path = layer_file_path(str(data_dir), layer_id)
        self.layer_id = layer_id
        self.config = ServiceConfig(data_dir=str(data_dir), admin_identities=[FIXTURE["admin"]])
        backend.initialize(self.path, json.loads(json.dumps(FIXTURE["shell"])), owner_of(backend))

    def load(self) -> dict:
        return self.backend.load(self.path)

    def restate(self, spec: dict, actor: LayerActor = ADMIN, **override):
        """Drive a restatement the way the REST service does: authorize, then apply."""
        block = {k: v for k, v in spec.items() if k not in ("stage", "rationale")}
        block.update(override)
        authorize_restatement(actor, block, self.config)
        return apply_restatement(
            self.layer_id,
            block,
            override.pop("rationale", spec["rationale"]),
            actor,
            NOW,
            self.writer,
            self.config,
        )

    def write_metadata(self, updates: dict) -> None:
        """The ordinary write path — what the harness does when baselining."""

        def _patch(layer: dict) -> None:
            layer.setdefault("metadata", {}).update(updates)

        self.backend.mutate(self.path, _patch)

    def append(self, event: dict) -> str:
        return self.writer.append_event(self.path, json.loads(json.dumps(event)))

    def stamp(self) -> None:
        from traust_ledger._internal.integrity import stamp_merkle_metadata

        self.backend.mutate(self.path, stamp_merkle_metadata)

    def errors(self) -> list:
        return [f for f in verify_merkle_integrity(self.load()) if f.severity == Severity.ERROR]


def _walk(harness: Harness) -> None:
    report_spec, claims_spec, artifacts_spec = FIXTURE["restatements"]
    baseline_claims = FIXTURE["baseline"]["claim_hashes"]

    # ── Stage 1: empty shell — there is nothing to restate ──────────────────
    # Scenario 1. A first entry is not a restatement: setting a field that was
    # never set destroys no prior value, so it needs no ticket and no admin.
    # Filing it as an administrative act would make routine baselining look
    # like a correction to data that never existed.
    with pytest.raises(NothingToRestateError):
        harness.restate(claims_spec, before=None)
    with pytest.raises(NothingToRestateError):
        harness.restate(report_spec)
    assert harness.load()["events"] == []
    assert "claim_hashes" not in harness.load()["metadata"]

    # ── Stage 2: baseline written through the ordinary path ─────────────────
    harness.write_metadata(FIXTURE["baseline"])
    harness.stamp()
    baseline = harness.load()
    assert baseline["metadata"]["claim_hashes"] == baseline_claims
    assert baseline["events"] == [], "baselining appends no events"

    # ── Stage 3: second event in the layer's life IS a restatement ──────────
    # Scenario 2. Nothing has been appended yet, so the restatement is the
    # layer's first event: the report was reissued and its digest moved.
    before_root = harness.load()["metadata"]["merkle_root"]
    result = harness.restate(report_spec)
    layer = harness.load()

    assert len(layer["events"]) == 1
    (event,) = layer["events"]
    assert is_restatement(event)
    assert event["event_id"] == result.event_id
    assert event["source"]["actor"]["identity"] == FIXTURE["admin"]
    assert event["restatement"]["before"] == report_spec["before"]
    assert event["restatement"]["authority"]["ticket"] == "SEC-4001"
    assert layer["metadata"]["audit_report_sha256"] == report_spec["after"]
    assert layer["metadata"]["merkle_root"] != before_root, "an append moves the root"
    assert harness.errors() == []

    # A restatement is not evidence: it must not surface as a finding.
    findings, _ = resolve_layer_findings(layer)
    assert findings == []

    # ── Stage 4: determinations, then a restatement over them ───────────────
    # Scenario 3. Three ordinary events across two findings, then a claim-hash
    # restatement. The restatement lands last and disturbs neither the events
    # nor the disposition they produce.
    for spec in FIXTURE["events"]:
        harness.append(spec)
    harness.stamp()

    with_events = harness.load()
    assert len(with_events["events"]) == 4
    findings_before, _ = resolve_layer_findings(with_events)
    dispositions_before = {f.finding_ref: f.disposition.validity for f in findings_before}
    assert len(dispositions_before) == 2
    stored_events_before = json.loads(json.dumps(with_events["events"]))

    harness.restate(claims_spec)
    final = harness.load()

    assert len(final["events"]) == 5
    assert final["events"][:4] == stored_events_before, "history is untouched"
    assert final["metadata"]["claim_hashes"] == claims_spec["after"]
    assert harness.errors() == []

    findings_after, _ = resolve_layer_findings(final)
    assert {f.finding_ref: f.disposition.validity for f in findings_after} == dispositions_before
    assert len(findings_after) == 2, "restatements add no findings"
    # Identity survives: every finding still reports the fingerprint its events
    # carry, and the layer-scoped restatements contribute none.
    assert all(f.fingerprint for f in findings_after)
    # claim_hashes is the baseline roster, so orphan detection reads the
    # RESTATED roster rather than the one the writer first pinned.
    assert all(f.orphan is False for f in findings_after)

    # Two restatements, two targets, each its own single-entry chain.
    assert len(restatements_for(final["events"], "audit_report_sha256")) == 1
    assert len(restatements_for(final["events"], "claim_hashes")) == 1
    assert terminal_value(final["events"], "claim_hashes") == (True, claims_spec["after"])

    # ── Stage 5: a repaired sibling artifact ────────────────────────────────
    # The common repair case: a sibling artifact is repaired, so one entry in
    # artifact_digests moves. That digest IS inside the signature, which is
    # what separates it from repairs touching unsigned fields only.
    harness.restate(artifacts_spec)
    repaired = harness.load()
    assert len(repaired["events"]) == 6
    assert repaired["metadata"]["artifact_digests"] == artifacts_spec["after"]
    changed = [
        name
        for name, digest in artifacts_spec["after"].items()
        if artifacts_spec["before"][name] != digest
    ]
    assert changed == ["acme-widget-remediation-verification.json"], "one sibling moved"
    assert harness.errors() == []

    # ── Stage 6: failure modes leave the layer byte-identical ───────────────
    # Scenario 4. Every refusal is checked against the SAME layer state, so a
    # gate that rejected but still wrote would show up as a diff here.
    snapshot = json.loads(json.dumps(repaired))

    failures: list[tuple[str, type[ServiceError], dict, LayerActor]] = [
        # not on the admin list
        ("outsider", NotAnAdminError, {}, OUTSIDER),
        # `before` describes a value the layer no longer holds
        ("stale before", StaleRestatementError, {"before": baseline_claims}, ADMIN),
        # authorised change to a field that did not move
        (
            "no-op",
            RestatementAuthorityError,
            {"before": claims_spec["after"], "after": claims_spec["after"]},
            ADMIN,
        ),
        # unattributed
        ("no ticket", RestatementAuthorityError, {"authority": {}}, ADMIN),
    ]
    for label, expected, override, actor in failures:
        with pytest.raises(expected):
            harness.restate(claims_spec, actor=actor, **override)
        assert harness.load() == snapshot, f"{label} must not write"

    # A machine cannot restate, however the call is shaped.
    with pytest.raises(ServiceError):
        harness.restate(
            claims_spec,
            actor=LayerActor(kind="machine", identity="harness/1.0.0", identity_verified=True),
        )
    # Nor an unverified human on the admin list.
    with pytest.raises(ServiceError):
        harness.restate(
            claims_spec,
            actor=LayerActor(kind="human", identity=FIXTURE["admin"], identity_verified=False),
        )
    # Rationale carries the why; without one the event records nothing useful.
    with pytest.raises(ServiceError):
        harness.restate(claims_spec, rationale="too short")

    assert harness.load() == snapshot
    assert harness.errors() == []


@pytest.mark.parametrize("backend_type", [BACKEND_TYPE_FILE, BACKEND_TYPE_DB])
def test_restatement_lifecycle(backend_type: str, tmp_path: Path) -> None:
    data_dir = tmp_path / "layers"
    if backend_type == BACKEND_TYPE_DB:
        prepare_storage(f"sqlite:///{tmp_path / 'ledger.db'}")
    backend = create_backend(
        backend_type,
        data_dir=data_dir,
        database_url=f"sqlite:///{tmp_path / 'ledger.db'}",
    )
    _walk(Harness(backend, data_dir, LAYER_ID))


@pytest.mark.integration
def test_restatement_lifecycle_postgresql(tmp_path: Path) -> None:
    url = os.environ.get("LEDGER_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LEDGER_TEST_DATABASE_URL is not configured")
    prepare_storage(url)
    _walk(
        Harness(
            create_backend(BACKEND_TYPE_DB, database_url=url),
            tmp_path,
            f"{LAYER_ID}-{uuid.uuid4().hex}",
        )
    )
