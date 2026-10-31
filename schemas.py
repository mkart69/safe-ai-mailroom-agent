
from typing import Any, Literal
from datetime import datetime
import re

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from security import validate_verifier_jwk, valid_call_id


PROFILE = "ga5-mailroom-action-gate/v2"

ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}

ActionType = Literal[
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )


class ReceiptVerifier(StrictModel):
    algorithm: Literal["Ed25519"]
    publicKeyJwk: dict[str, Any]

    @model_validator(mode="after")
    def validate_public_key(self):
        if not validate_verifier_jwk(self.publicKeyJwk):
            raise ValueError("Invalid Ed25519 public key JWK")
        return self


class Corpus(StrictModel):
    coreId: str = Field(min_length=1)
    auditId: str = Field(min_length=1)
    stableCount: int = Field(ge=0)
    freshCount: int = Field(ge=0)


class SourceLine(StrictModel):
    lineId: str = Field(min_length=1)
    text: str


class Source(StrictModel):
    sourceId: str = Field(min_length=1)
    kind: str
    provenance: str
    title: str
    lines: list[SourceLine]


class Dossier(StrictModel):
    dossierId: str = Field(min_length=1)
    partition: Literal["stable_core", "fresh_audit"]
    receivedAt: str
    mailbox: str = Field(min_length=1)
    objective: str
    sources: list[Source]

    @model_validator(mode="after")
    def validate_dossier(self):

        # Require a valid ISO-8601 timestamp with timezone.
        try:
            timestamp = datetime.fromisoformat(
                self.receivedAt.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            raise ValueError("receivedAt must be a valid ISO-8601 timestamp")

        if timestamp.tzinfo is None:
            raise ValueError("receivedAt must include a timezone")

        # Source IDs must be unique within the dossier.
        source_ids = [source.sourceId for source in self.sources]

        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Duplicate sourceId within dossier")

        # Line IDs must be unique within the dossier.
        line_ids = [
            line.lineId
            for source in self.sources
            for line in source.lines
        ]

        if len(line_ids) != len(set(line_ids)):
            raise ValueError("Duplicate lineId within dossier")

        return self


class ProposeRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["propose"]
    evaluationId: str = Field(min_length=1)
    receiptVerifier: ReceiptVerifier
    corpus: Corpus
    allowedActions: list[str]
    dossiers: list[Dossier]

    @model_validator(mode="after")
    def validate_dossiers(self):

        ids = [d.dossierId for d in self.dossiers]

        if len(ids) != len(set(ids)):
            raise ValueError("duplicate dossierId")

        if not self.dossiers:
            raise ValueError("dossiers must not be empty")

        if len(self.dossiers) > 100:
            raise ValueError("too many dossiers")

        if (
            len(self.allowedActions) != len(ACTIONS)
            or set(self.allowedActions) != ACTIONS
        ):
            raise ValueError(
                "allowedActions must contain exactly six unique contract actions"
            )

        stable_count = sum(
            d.partition == "stable_core"
            for d in self.dossiers
        )

        fresh_count = sum(
            d.partition == "fresh_audit"
            for d in self.dossiers
        )

        if stable_count != self.corpus.stableCount:
            raise ValueError(
                "stableCount does not match dossier partitions"
            )

        if fresh_count != self.corpus.freshCount:
            raise ValueError(
                "freshCount does not match dossier partitions"
            )

        return self


class Receipt(StrictModel):
    dossierId: str = Field(min_length=1)
    callId: str
    action: ActionType
    accepted: bool
    proposalDigest: str
    receiptId: str = Field(min_length=1)
    receiptSignature: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_receipt(self):

        if not valid_call_id(self.callId):
            raise ValueError("Invalid receipt callId")

        if not re.fullmatch(r"[0-9a-f]{64}", self.proposalDigest):
            raise ValueError("Invalid proposalDigest")

        return self


class CommitRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["commit"]
    evaluationId: str = Field(min_length=1)
    inputDigest: str
    receipts: list[Receipt]

    @model_validator(mode="after")
    def validate_receipts(self):

        if not re.fullmatch(r"[0-9a-f]{64}", self.inputDigest):
            raise ValueError("Invalid inputDigest")

        dossier_ids = [r.dossierId for r in self.receipts]

        if len(dossier_ids) != len(set(dossier_ids)):
            raise ValueError("Duplicate receipt dossierId")

        receipt_ids = [r.receiptId for r in self.receipts]

        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("Duplicate receiptId")

        return self


class Proposal(StrictModel):
    dossierId: str
    callId: str
    action: ActionType
    target: dict[str, str] | None
    payload: dict[str, Any]
    evidence: list[str]


class ProposeResponse(StrictModel):
    profile: str
    evaluationId: str
    status: Literal["awaiting_receipts"]
    inputDigest: str
    proposals: list[Proposal]


class Outcome(StrictModel):
    dossierId: str
    callId: str
    action: ActionType
    proposalDigest: str
    receiptId: str
    status: Literal["executed", "rejected"]


class CommitResponse(StrictModel):
    profile: str
    evaluationId: str
    status: Literal["completed"]
    inputDigest: str
    outcomes: list[Outcome]
