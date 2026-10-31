
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from canonical import canonical_json
from security import verify_receipt


PROFILE = "ga5-mailroom-action-gate/v2"

# Generate a temporary Ed25519 key pair
private_key = Ed25519PrivateKey.generate()

public_bytes = private_key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw
)

public_x = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")

jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": public_x
}

evaluation_id = "TEST-EVAL-001"
input_digest = "a" * 64

# Create the unsigned receipt
receipt = {
    "dossierId": "TEST-001",
    "callId": "call_TEST_123456",
    "action": "no_action",
    "accepted": True,
    "proposalDigest": "b" * 64,
    "receiptId": "receipt_TEST_001"
}

# Build the exact object that must be signed
signed_object = {
    "profile": PROFILE,
    "evaluationId": evaluation_id,
    "inputDigest": input_digest,
    "receipt": receipt
}

# Sign canonical JSON
signed_bytes = canonical_json(signed_object).encode("utf-8")
signature = private_key.sign(signed_bytes)

# Add the Base64-encoded signature
receipt["receiptSignature"] = base64.b64encode(signature).decode("ascii")

# Test 1: Valid signature
valid_result = verify_receipt(
    receipt, jwk, evaluation_id, input_digest
)
print("Valid signature accepted:", valid_result)

# Test 2: Modified receipt
tampered_receipt = dict(receipt)
tampered_receipt["action"] = "send_approved_notice"

tampered_result = verify_receipt(
    tampered_receipt, jwk, evaluation_id, input_digest
)
print("Tampered receipt rejected:", not tampered_result)

# Test 3: Wrong evaluation ID
wrong_eval_result = verify_receipt(
    receipt, jwk, "DIFFERENT-EVALUATION", input_digest
)
print("Wrong evaluation ID rejected:", not wrong_eval_result)
