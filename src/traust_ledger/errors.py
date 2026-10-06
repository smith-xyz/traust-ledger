"""Domain errors — plain exceptions categorized by kind.

No framework dependencies. The REST layer maps error categories to HTTP status
codes; the CLI maps them to exit codes; the LedgerClient maps them to LedgerError.

Categories:
    ServiceError        — base (validation failures, 422-equivalent)
    AuthError           — authentication/authorization failures
    NotFoundError       — resource not found
    InternalError       — unexpected failures (signing, etc.)
"""

from __future__ import annotations

from typing import ClassVar


class ServiceError(Exception):
    """Base domain error. Represents a validation/business-rule failure."""

    message: ClassVar[str] = ""

    def __init__(self, **kwargs: object) -> None:
        detail = type(self).format_message(**kwargs)
        super().__init__(detail)
        self.detail = detail

    @classmethod
    def format_message(cls, **kwargs: object) -> str:
        if kwargs:
            return cls.message.format(**kwargs)
        return cls.message


class AuthError(ServiceError):
    """Authentication or authorization failure."""

    message = "authentication required"


class ForbiddenError(ServiceError):
    """Authenticated but not permitted — 403, not 401.

    Telling a caller with a valid token to re-authenticate cannot help.
    """

    message = "{detail}"


class NotFoundError(ServiceError):
    """Requested resource does not exist."""

    message = "{detail}"


class InternalError(ServiceError):
    """Unexpected internal failure."""

    message = "{detail}"


class ValidationError(ServiceError):
    """Generic validation error."""

    message = "{detail}"


# ─── Specific domain errors ──────────────────────────────────────────────


class MissingAuthError(AuthError):
    message = "authentication required"


class InvalidAuthError(AuthError):
    message = "invalid credentials"


class InvalidKindError(ServiceError):
    message = "unknown report kind: {kind}"


class IdentityRequiredError(ServiceError):
    message = "human identity required for this event kind"


class IdentityUnverifiedError(ServiceError):
    message = "verified identity required for human false_positive"


class TwoPersonViolatedError(ServiceError):
    message = "two-person rule: same human cannot satisfy both signatures"


class MachineDispositionError(ServiceError):
    message = "machine actors cannot submit disposition events"


class RationaleTooShortError(ServiceError):
    message = "rationale must be at least {min_length} characters"


class TimestampFutureError(ServiceError):
    message = "recorded_at cannot be more than {hours}h in the future"


class InvalidEpochError(ServiceError):
    message = "metadata.merkle_epoch is invalid for the current events array"


class LayerNotFoundError(NotFoundError):
    message = "layer not found: {layer_id}"


class ProductRepoLayerNotFoundError(NotFoundError):
    message = "no layer for product_repo: {product_repo_id}"


class SigningRequiredError(ServiceError):
    message = (
        "signing is required but no signer is configured — "
        "set LAAS_SIGNING_KEY_PATH (keypair) or configure sigstore-oidc; "
        "nothing was written"
    )


class SigningFailedError(InternalError):
    message = (
        "signing failed for {layer_id} — set LAAS_SIGNING_KEY_PATH and "
        "COSIGN_PASSWORD (keypair), or configure sigstore-oidc; "
        "nothing was written (atomic rollback)"
    )

    def __init__(self, *, layer_id: str = "unknown", **kwargs: object) -> None:
        super().__init__(layer_id=layer_id, **kwargs)


class MissingLayerIdError(ServiceError):
    message = "layer_id is required"


class MissingSeverityError(ServiceError):
    message = "severity level is required for severity events"


class MissingDecisionOrVerdictError(ServiceError):
    message = "decision or verdict is required for countersign events"


class DecisionVerdictConflictError(ServiceError):
    message = "decision and verdict both present but disagree; provide one, not both"


class UnknownDecisionError(ServiceError):
    message = "unknown decision value: {decision}"


class MissingFindingRefError(ServiceError):
    message = "finding_ref (or finding_fingerprint) is required"


class MissingRecordedAtEventError(ServiceError):
    message = "recorded_at is required in event payload"


class InvalidLayerIdError(ServiceError):
    message = "layer_id contains invalid characters"


class CorruptStoredEventError(InternalError):
    """A stored event violates a contract invariant it should not be able to.

    Raised on read, so the message must identify the event: without it the
    failure is an anonymous 500 over a corpus of thousands of layers.
    """

    message = "event {event_id} has {field}={value!r}, which is not RFC 3339"


class EventIdMismatchError(ServiceError):
    message = "event_id mismatch: supplied '{supplied}' != canonical '{canonical}'"


class NotAnAdminError(ForbiddenError):
    message = (
        "{identity} is not a ledger administrator — restatements rewrite "
        "signature-bound data and are restricted to the configured admin set"
    )


class RestatementAuthorityError(ServiceError):
    message = "{detail}"


class NothingToRestateError(ServiceError):
    """The target field holds no value, so there is nothing to restate."""

    message = (
        "metadata.{target} holds no value — there is nothing to restate. "
        "Setting it the first time destroys no prior value and needs no ticket; "
        "write it through the ordinary path instead"
    )


class RetiredValueRestatedError(ServiceError):
    """The chain already moved away from this value."""

    message = (
        "restatement of {target} restores a value the chain already retired ({keys}) — "
        "reversing an earlier restatement is its own decision and needs its own "
        "reason, not a rollback to a superseded value"
    )


class InsufficientApproversError(ForbiddenError):
    message = (
        "this deployment requires {required} independent approver(s) on a "
        "restatement; found {found} in authority.approved_by"
    )


class StaleRestatementError(ServiceError):
    """``before`` disagrees with what is stored — the concurrent-write guard."""

    message = (
        "restatement for {target} does not match the stored value — "
        "`before` says {before!r}, the layer holds {actual!r}; "
        "re-read the layer and recompute the restatement"
    )


class UnexplainedMetadataChangeError(ServiceError):
    """A signature-bound metadata field changed with nothing to explain it."""

    message = (
        "metadata.{field} changed without a restatement event recording it — "
        "the value is inside the signature, so rewriting it silently destroys "
        "the only evidence of what it was; append a restatement instead"
    )


__all__ = [
    "AuthError",
    "CorruptStoredEventError",
    "DecisionVerdictConflictError",
    "EventIdMismatchError",
    "ForbiddenError",
    "IdentityRequiredError",
    "IdentityUnverifiedError",
    "InsufficientApproversError",
    "InternalError",
    "InvalidAuthError",
    "InvalidEpochError",
    "InvalidKindError",
    "InvalidLayerIdError",
    "LayerNotFoundError",
    "MachineDispositionError",
    "MissingAuthError",
    "MissingDecisionOrVerdictError",
    "MissingFindingRefError",
    "MissingLayerIdError",
    "MissingRecordedAtEventError",
    "MissingSeverityError",
    "NotAnAdminError",
    "NotFoundError",
    "NothingToRestateError",
    "ProductRepoLayerNotFoundError",
    "RationaleTooShortError",
    "RestatementAuthorityError",
    "RetiredValueRestatedError",
    "ServiceError",
    "SigningFailedError",
    "SigningRequiredError",
    "StaleRestatementError",
    "TimestampFutureError",
    "TwoPersonViolatedError",
    "UnexplainedMetadataChangeError",
    "UnknownDecisionError",
    "ValidationError",
]
