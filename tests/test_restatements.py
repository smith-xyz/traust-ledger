"""Administrative restatements — projection, gates, and the write-path invariant.

The property under test is one sentence: **a signature-bound value may only
change in a write that also records what it was, who changed it, and why.**

Before this existed, `LedgerClient.patch_metadata` would rewrite
`claim_hashes` / `audit_report_sha256` / `artifact_digests` and re-sign with no
record of any of the three, so an authorised restatement and a tampering rewrite
left the layer in byte-identical states. The only signal — a digest mismatch —
had to be adjudicated by a human every time, which is why
`check_report_digest`'s message ends in "decide by hand".

Event content is the mirror-image problem: immutable (DB prefix check + Merkle
leaf_format 2), so a wrong field can only be superseded by an overlay applied
on READ. These tests pin that the stored bytes and the Merkle root never move
when that happens.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from storage_db import owner_of, prepare_storage
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.events.builders import (
    build_restatement_event,
    restatement_source_ref,
)
from traust_ledger._internal.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)
from traust_ledger._internal.restatements import (
    LAYER_SCOPE_REF,
    apply_restatements,
    is_restatement,
    terminal_value,
)
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.api.findings import resolve_layer_findings
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import (
    NotAnAdminError,
    NothingToRestateError,
    RestatementAuthorityError,
    ServiceError,
    StaleRestatementError,
    UnexplainedMetadataChangeError,
)
from traust_ledger.handlers.restatement_handler import apply_restatement
from traust_ledger.paths import layer_file_path
from traust_ledger.service.auth import authorize_restatement

ADMIN = "admin@example.com"
LAYER_ID = "repo-correct"
FAKE_TOKEN = "unused-the-verifier-is-stubbed"


class _AdminVerifier:
    def verify(self, token: str) -> LayerActor:
        return LayerActor(kind="human", identity=ADMIN, identity_verified=True)


ADMIN_ACTOR = LayerActor(
    kind="human",
    identity=ADMIN,
    identity_verified=True,
    identity_provider="oidc",
)
USER_ACTOR = LayerActor(
    kind="human",
    identity="dev@example.com",
    identity_verified=True,
    identity_provider="oidc",
)
MACHINE_ACTOR = LayerActor(kind="machine", identity="harness/1.0.0", identity_verified=True)

RATIONALE = "Baseline report reissued after the v1->v2 fingerprint re-stamp."
NOW = "2026-09-25T12:00:00+00:00"


def _block(**over) -> dict:
    block = {
        "target": "claim_hashes",
        "reason": "baseline_rewrite",
        "before": {"FIND-1": "a" * 64},
        "after": {"FIND-1": "b" * 64},
        "authority": {"ticket": "SEC-1234"},
    }
    block.update(over)
    return block


def _finding_event(source_ref: str, *, validity: str = "confirmed", **over) -> dict:
    event = {
        "finding_ref": "FIND-1",
        "recorded_at": "2026-09-01T10:00:00+00:00",
        "occurred_at": "2026-09-01T10:00:00+00:00",
        "source": {
            "type": "triage_report",
            "ref": source_ref,
            "actor": {"kind": "machine", "identity": "scanner/1.0.0"},
        },
        "disposition": {"validity": validity},
        "rationale": f"machine determination from {source_ref}",
    }
    event.update(over)
    return event


def _seed(
    tmp_path: Path, *, claim_hashes: dict | None = None
) -> tuple[LedgerWriter, ServiceConfig]:
    backend = FileBackend(data_dir=tmp_path)
    metadata: dict = {
        "audit_report": "audit.json",
        "repository": "https://example.test/repo",
        "created": "2026-09-01T10:00:00+00:00",
        "harness_version": "1.0.0",
    }
    if claim_hashes is not None:
        metadata["claim_hashes"] = claim_hashes
    backend.initialize(
        layer_file_path(str(tmp_path), LAYER_ID),
        {"metadata": metadata, "events": [], "needs_review": []},
        owner_of(backend),
    )
    config = ServiceConfig(data_dir=str(tmp_path), admin_identities=[ADMIN])
    return LedgerWriter(backend=backend), config


def _load(tmp_path: Path) -> dict:
    return FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))


# ── Pure projection ──────────────────────────────────────────────────────────


class TestProjection:
    def test_restatement_is_recognised_only_from_a_restatement_source(self) -> None:
        """A hand-written layer could put a restatement block on an ordinary
        determination. It must not thereby acquire the authority to rewrite
        metadata, so both halves are checked."""
        event = build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW).to_dict()
        assert is_restatement(event)
        smuggled = {**event, "source": {**event["source"], "type": "interactive"}}
        assert not is_restatement(smuggled)

    def test_restatements_never_reach_the_precedence_engine(self) -> None:
        events = [
            _finding_event("scan-1.json"),
            build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW).to_dict(),
        ]
        projected = apply_restatements(events)
        assert [e["source"]["type"] for e in projected] == ["triage_report"]

    def test_event_content_is_not_correctable(self) -> None:
        """Events are immutable; a wrong determination is superseded by a later
        one under latest-wins precedence. A read-time overlay would be a second
        read-time transform competing with the v1->v2 normaliser, with no
        defined ordering between them (classifier-disposition plan R1, D13)."""
        from traust_contracts.v1.enums import RestatementTarget

        assert "event" not in {target.value for target in RestatementTarget}

    def test_ordinary_events_pass_through_untouched(self) -> None:
        events = [_finding_event("scan-1.json", event_id="d" * 64)]
        assert apply_restatements(events) == events

    def test_terminal_value_distinguishes_uncorrected_from_corrected_to_none(self) -> None:
        assert terminal_value([], "claim_hashes") == (False, None)
        block = _block(after=None, before={"FIND-1": "a" * 64})
        events = [build_restatement_event(block, RATIONALE, ADMIN_ACTOR, NOW).to_dict()]
        assert terminal_value(events, "claim_hashes") == (True, None)

    def test_layer_scoped_restatement_is_not_counted_as_a_finding(self) -> None:
        """LAYER_SCOPE_REF keeps envelope restatements out of finding streams.
        A plausible-looking finding id would make resolve_layer_findings report
        an event for a finding nothing ever said anything about."""
        layer = {
            "metadata": {},
            "events": [
                _finding_event("scan-1.json", event_id="d" * 64),
                build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW).to_dict(),
            ],
        }
        findings, _ = resolve_layer_findings(layer)
        assert [f.finding_ref for f in findings] == ["FIND-1"]
        assert findings[0].event_count == 1


# ── Builder ──────────────────────────────────────────────────────────────────


class TestBuilder:
    def test_distinct_restatements_get_distinct_event_ids(self) -> None:
        """The collision trap. compute_event_id hashes
        source_ref|finding_ref|validity|resolution, and a restatement has an
        empty disposition — so a fixed source_ref would make every restatement
        to the same finding compute the SAME id, and _append_one would drop the
        second as a duplicate while reporting success."""
        first = build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW)
        second = build_restatement_event(
            _block(before={"FIND-1": "b" * 64}, after={"FIND-1": "c" * 64}),
            RATIONALE,
            ADMIN_ACTOR,
            NOW,
        )
        assert first.event_id != second.event_id
        assert first.source.ref != second.source.ref

    def test_source_ref_is_deterministic(self) -> None:
        assert restatement_source_ref(_block(), ADMIN, NOW) == restatement_source_ref(
            _block(), ADMIN, NOW
        )

    def test_disposition_is_always_empty(self) -> None:
        event = build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW).to_dict()
        assert event.get("disposition", {}) == {}
        assert event["finding_ref"] == LAYER_SCOPE_REF

    def test_writer_refuses_a_restatement_carrying_a_disposition(self, tmp_path: Path) -> None:
        writer, _ = _seed(tmp_path)
        event = build_restatement_event(_block(), RATIONALE, ADMIN_ACTOR, NOW).to_dict()
        event["disposition"] = {"validity": "false_positive"}
        with pytest.raises(ValueError, match="empty disposition"):
            writer.append_event(layer_file_path(str(tmp_path), LAYER_ID), event)


# ── Gates ────────────────────────────────────────────────────────────────────


class TestGates:
    def _apply(self, tmp_path: Path, actor: LayerActor, **over) -> None:
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        apply_restatement(LAYER_ID, _block(**over), RATIONALE, actor, NOW, writer, config)

    def test_handler_does_not_authorize(self, tmp_path: Path) -> None:
        """Who may restate is decided at the REST boundary. In-process callers own
        their config, so the handler records the actor instead of checking a
        list that caller could edit."""
        self._apply(tmp_path, USER_ACTOR)
        (event,) = _load(tmp_path)["events"]
        assert event["source"]["actor"]["identity"] == USER_ACTOR.identity

    def test_machine_is_refused(self, tmp_path: Path) -> None:
        """Attribution, not permission: a restatement is a human decision."""
        with pytest.raises(ServiceError):
            self._apply(tmp_path, MACHINE_ACTOR)

    def test_unverified_actor_is_refused(self, tmp_path: Path) -> None:
        unverified = LayerActor(kind="human", identity=ADMIN, identity_verified=False)
        with pytest.raises(ServiceError):
            self._apply(tmp_path, unverified)

    def test_ticket_is_required(self, tmp_path: Path) -> None:
        with pytest.raises(RestatementAuthorityError, match=r"authority\.ticket"):
            self._apply(tmp_path, ADMIN_ACTOR, authority={})

    def test_no_op_restatement_is_refused(self, tmp_path: Path) -> None:
        """An authorised change to a field that did not move is the shape of a
        cover story, not a restatement."""
        same = {"FIND-1": "a" * 64}
        with pytest.raises(RestatementAuthorityError, match="changes nothing"):
            self._apply(tmp_path, ADMIN_ACTOR, before=same, after=same)

    def test_restating_an_unset_field_is_refused(self, tmp_path: Path) -> None:
        """A first entry is not a restatement: setting a field that was never
        set destroys no prior value, so it belongs on the ordinary write path."""
        writer, config = _seed(tmp_path)
        block = _block()
        del block["before"]
        with pytest.raises(NothingToRestateError):
            apply_restatement(LAYER_ID, block, RATIONALE, ADMIN_ACTOR, NOW, writer, config)

    def test_stale_before_is_refused(self, tmp_path: Path) -> None:
        """Two admins correcting the same field from the same read would both
        succeed, and the loser's value would vanish while the log recorded both
        as applied."""
        with pytest.raises(StaleRestatementError):
            self._apply(tmp_path, ADMIN_ACTOR, before={"FIND-1": "9" * 64})

    def test_short_rationale_is_refused(self, tmp_path: Path) -> None:
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        with pytest.raises(ServiceError):
            apply_restatement(LAYER_ID, _block(), "short", ADMIN_ACTOR, NOW, writer, config)


class TestServiceAuthorization:
    """``authorize_restatement`` — the REST boundary's admin/approver check."""

    def test_non_admin_is_refused(self) -> None:
        config = ServiceConfig(admin_identities=[ADMIN])
        with pytest.raises(NotAnAdminError):
            authorize_restatement(USER_ACTOR, _block(), config)

    def test_empty_admin_set_fails_closed(self) -> None:
        """An unconfigured deployment grants the power to nobody, not everybody."""
        with pytest.raises(NotAnAdminError):
            authorize_restatement(ADMIN_ACTOR, _block(), ServiceConfig(admin_identities=[]))

    def test_admin_match_is_case_insensitive(self) -> None:
        shouty = LayerActor(kind="human", identity=ADMIN.upper(), identity_verified=True)
        authorize_restatement(shouty, _block(), ServiceConfig(admin_identities=[ADMIN]))

    def test_machine_admin_is_refused(self) -> None:
        machine = LayerActor(kind="machine", identity=ADMIN, identity_verified=True)
        with pytest.raises(ServiceError):
            authorize_restatement(machine, _block(), ServiceConfig(admin_identities=[ADMIN]))


# ── Write path ───────────────────────────────────────────────────────────────


class TestWritePath:
    def test_restatement_applies_metadata_and_records_the_prior_value(self, tmp_path: Path) -> None:
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        result = apply_restatement(LAYER_ID, _block(), RATIONALE, ADMIN_ACTOR, NOW, writer, config)
        layer = _load(tmp_path)
        assert layer["metadata"]["claim_hashes"] == {"FIND-1": "b" * 64}
        (event,) = layer["events"]
        assert event["event_id"] == result.event_id
        assert event["restatement"]["before"] == {"FIND-1": "a" * 64}
        assert event["restatement"]["authority"]["ticket"] == "SEC-1234"
        assert event["source"]["actor"]["identity"] == ADMIN

    def test_root_moves_and_the_layer_stays_verifiable(self, tmp_path: Path) -> None:
        """A restatement re-signs for free: it is an append, so the root moves
        and the ordinary finalize path re-stamps. That is why no signature
        format 5 is needed — format 4 already binds the root and the digests."""
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        writer.append_event(layer_file_path(str(tmp_path), LAYER_ID), _finding_event("scan.json"))
        writer.backend.mutate(layer_file_path(str(tmp_path), LAYER_ID), stamp_merkle_metadata)
        before_root = _load(tmp_path)["metadata"]["merkle_root"]

        apply_restatement(LAYER_ID, _block(), RATIONALE, ADMIN_ACTOR, NOW, writer, config)

        layer = _load(tmp_path)
        assert layer["metadata"]["merkle_root"] != before_root
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    def test_two_successive_restatements_both_land(self, tmp_path: Path) -> None:
        """Guards the silent-duplicate trap end to end."""
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        apply_restatement(LAYER_ID, _block(), RATIONALE, ADMIN_ACTOR, NOW, writer, config)
        apply_restatement(
            LAYER_ID,
            _block(before={"FIND-1": "b" * 64}, after={"FIND-1": "c" * 64}),
            RATIONALE,
            ADMIN_ACTOR,
            NOW,
            writer,
            config,
        )
        layer = _load(tmp_path)
        assert len(layer["events"]) == 2
        assert layer["metadata"]["claim_hashes"] == {"FIND-1": "c" * 64}

    def test_uncovered_metadata_change_is_refused(self, tmp_path: Path) -> None:
        """The load-bearing invariant. A write that moves a signed digest while
        appending a restatement for something else must fail — otherwise the
        restatement event becomes cover for an unrelated rewrite."""
        writer, _config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        event = build_restatement_event(
            _block(target="audit_report_sha256", before="0" * 64, after="9" * 64),
            RATIONALE,
            ADMIN_ACTOR,
            NOW,
        ).to_dict()
        with pytest.raises(UnexplainedMetadataChangeError, match="claim_hashes"):
            writer.append_restatement(
                layer_file_path(str(tmp_path), LAYER_ID),
                event,
                {"audit_report_sha256": "9" * 64, "claim_hashes": {"FIND-1": "9" * 64}},
                None,
            )
        assert _load(tmp_path)["metadata"]["claim_hashes"] == {"FIND-1": "a" * 64}
        assert _load(tmp_path)["events"] == []

    def test_patch_metadata_may_make_a_first_write(self, tmp_path: Path) -> None:
        """Pinning a value that was never recorded destroys no evidence, and is
        routine harness work (baseline_claims record). Only overwrites need a
        restatement."""
        from traust_ledger._internal.integrity.signing import SigningConfig
        from traust_ledger.client import LedgerClient

        _seed(tmp_path)
        client = LedgerClient(
            token=FAKE_TOKEN,
            verifier=_AdminVerifier(),
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
        )
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"FIND-1": "a" * 64}})
        assert _load(tmp_path)["metadata"]["claim_hashes"] == {"FIND-1": "a" * 64}

    def test_patch_metadata_may_add_a_new_claim(self, tmp_path: Path) -> None:
        """Per key: baselining a NEW finding is an addition, not an overwrite."""
        from traust_ledger._internal.integrity.signing import SigningConfig
        from traust_ledger.client import LedgerClient

        _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        client = LedgerClient(
            token=FAKE_TOKEN,
            verifier=_AdminVerifier(),
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
        )
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"FIND-2": "b" * 64}})
        assert _load(tmp_path)["metadata"]["claim_hashes"] == {
            "FIND-1": "a" * 64,
            "FIND-2": "b" * 64,
        }

    def test_patch_metadata_cannot_overwrite_a_signed_digest(self, tmp_path: Path) -> None:
        """The hole this mechanism closes, asserted at the door it came through."""
        from traust_ledger._internal.integrity.signing import SigningConfig
        from traust_ledger.client import LedgerClient, LedgerError

        _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        client = LedgerClient(
            token=FAKE_TOKEN,
            verifier=_AdminVerifier(),
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
        )
        with pytest.raises(LedgerError, match="use restate"):
            client.patch_metadata(LAYER_ID, {"claim_hashes": {"FIND-1": "b" * 64}})
        assert _load(tmp_path)["metadata"]["claim_hashes"] == {"FIND-1": "a" * 64}

        client.patch_metadata(LAYER_ID, {"audit_report_sha256": "c" * 64})
        with pytest.raises(LedgerError, match="use restate"):
            client.patch_metadata(LAYER_ID, {"audit_report_sha256": "d" * 64})


# ── Verification ─────────────────────────────────────────────────────────────


class TestVerification:
    def _corrected_layer(self, tmp_path: Path) -> dict:
        writer, config = _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        apply_restatement(LAYER_ID, _block(), RATIONALE, ADMIN_ACTOR, NOW, writer, config)
        return _load(tmp_path)

    def test_corrected_layer_verifies(self, tmp_path: Path) -> None:
        layer = self._corrected_layer(tmp_path)
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    def test_out_of_band_rewrite_after_a_restatement_is_an_error(self, tmp_path: Path) -> None:
        layer = self._corrected_layer(tmp_path)
        layer["metadata"]["claim_hashes"] = {"FIND-1": "9" * 64}
        stamp_merkle_metadata(layer)  # re-stamping does not launder it
        errors = [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]
        assert any("restatement chain" in f.message for f in errors)

    def test_removing_the_restatement_event_is_refused_by_storage(self, tmp_path: Path) -> None:
        """Deleting the evidence while keeping its effect.

        Verification alone cannot catch this: with the event gone there is no
        chain to compare against, and the layer is indistinguishable from one
        that never corrected anything. Storage is what refuses it \u2014 the DB
        backend requires the stored event payloads to be an exact prefix of
        what is written. Recorded here rather than left implicit, because the
        limit matters: on the file backend, an attacker who can rewrite the
        layer AND re-sign can erase a restatement, exactly as they could already
        erase any other event.
        """
        from sqlalchemy import create_engine

        from traust_ledger._internal.backends.db import DbBackend
        from traust_ledger._internal.backends.errors import LayerConflictError

        layer = self._corrected_layer(tmp_path)
        engine = create_engine(f"sqlite:///{tmp_path / 'ledger.db'}")
        prepare_storage(engine)
        DbBackend.create_tables(engine)
        backend = DbBackend(engine)
        path = Path(f"{LAYER_ID}.json")
        backend.initialize(path, {**layer, "events": []}, owner_of(backend))
        backend.store(path, layer)

        stripped = {**layer, "events": []}
        with pytest.raises(LayerConflictError, match="cannot remove"):
            backend.store(path, stripped)

    def test_uncorrected_layers_are_not_examined(self, tmp_path: Path) -> None:
        """A field with no restatement chain has nothing to compare against —
        which is exactly the gap the vocabulary closes going forward, and why
        the check must not invent a verdict for layers written before it
        existed."""
        _seed(tmp_path, claim_hashes={"FIND-1": "a" * 64})
        layer = _load(tmp_path)
        stamp_merkle_metadata(layer)
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]


class TestOverwriteOnlyGating:
    """First writes and additions are not restatements.

    `baseline_claims record` pins claim hashes for findings that have none, as
    the harness, on every audit. Gating that would force an admin identity into
    a machine path and record a "restatement" for data nobody had recorded yet.
    """

    @pytest.mark.parametrize(
        ("prior", "new", "destructive"),
        [
            (None, {"A": "1"}, False),
            ({}, {"A": "1"}, False),
            ({"A": "1"}, {"A": "1", "B": "2"}, False),
            ({"A": "1"}, {"A": "1"}, False),
            ({"A": "1"}, {"A": "2"}, True),
            ({"A": "1", "B": "2"}, {"A": "1"}, True),
            (None, "digest", False),
            ("digest", "digest", False),
            ("digest", "other", True),
        ],
    )
    def test_destructive_change(self, prior: object, new: object, destructive: bool) -> None:
        from traust_ledger._internal.restatements import is_destructive_change

        assert is_destructive_change(prior, new) is destructive

    def test_writer_allows_a_first_write_without_a_restatement(self, tmp_path: Path) -> None:
        writer, _config = _seed(tmp_path)
        path = layer_file_path(str(tmp_path), LAYER_ID)

        def _stamp(layer: dict) -> None:
            layer["metadata"]["claim_hashes"] = {"FIND-1": "a" * 64}

        writer.backend.mutate(path, _stamp)
        assert _load(tmp_path)["metadata"]["claim_hashes"] == {"FIND-1": "a" * 64}
