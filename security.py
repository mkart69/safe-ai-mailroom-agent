
import base64
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from canonical import canonical_json


PROFILE = "ga5-mailroom-action-gate/v2"

RECEIPT_FIELDS = {
    "dossierId",
    "callId",
    "action",
    "accepted",
    "proposalDigest",
    "receiptId",
    "receiptSignature",
}


def b64url_decode(value: str) -> bytes:
    """Strictly decode an unpadded Base64URL value."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid Base64URL value")

    padded = value + "=" * (-len(value) % 4)
    decoded = base64.b64decode(
        padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )

    # Reject non-canonical encodings.
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError("Non-canonical Base64URL value")

    return decoded


def validate_verifier_jwk(verifier_jwk: dict) -> bool:
    """Check that the supplied JWK is a valid Ed25519 public key."""
    try:
        if not isinstance(verifier_jwk, dict):
            return False

        if set(verifier_jwk) != {"kty", "crv", "x"}:
            return False

        if verifier_jwk["kty"] != "OKP":
            return False

        if verifier_jwk["crv"] != "Ed25519":
            return False

        public_bytes = b64url_decode(verifier_jwk["x"])

        if len(public_bytes) != 32:
            return False

        Ed25519PublicKey.from_public_bytes(public_bytes)
        return True

    except (ValueError, TypeError, KeyError):
        return False


def verify_receipt(
    receipt: dict,
    verifier_jwk: dict,
    evaluation_id: str,
    input_digest: str,
) -> bool:
    """Verify an Ed25519 signature over the canonical receipt object."""

    try:
        if not isinstance(receipt, dict):
            return False

        if set(receipt) != RECEIPT_FIELDS:
            return False

        if not validate_verifier_jwk(verifier_jwk):
            return False

        if type(receipt["accepted"]) is not bool:
            return False

        for field in RECEIPT_FIELDS - {"accepted"}:
            if not isinstance(receipt[field], str) or not receipt[field]:
                return False

        public_bytes = b64url_decode(verifier_jwk["x"])
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

        signature_text = receipt["receiptSignature"]

        signature = base64.b64decode(
            signature_text.encode("ascii"),
            validate=True,
        )

        if len(signature) != 64:
            return False

        unsigned_receipt = {
            key: value
            for key, value in receipt.items()
            if key != "receiptSignature"
        }

        signed_object = {
            "profile": PROFILE,
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": unsigned_receipt,
        }

        signed_bytes = canonical_json(signed_object).encode("utf-8")

        public_key.verify(signature, signed_bytes)
        return True

    except Exception:
        return False


def valid_call_id(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9._:-]{12,128}", value)
    )
