
import base64
import uuid
import httpx

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

URL = "http://127.0.0.1:8000/v1/mailroom/actions"

def make_jwk():
    key = Ed25519PrivateKey.generate()
    public_bytes = key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes)
            .rstrip(b"=").decode("ascii")
    }

evaluation_id = "REPLAY-TEST-" + uuid.uuid4().hex

request_data = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": evaluation_id,
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": make_jwk()
    },
    "corpus": {
        "coreId": "test-core",
        "auditId": "test-audit",
        "stableCount": 1,
        "freshCount": 0
    },
    "allowedActions": [
        "create_draft",
        "update_internal_record",
        "send_approved_notice",
        "request_confirmation",
        "quarantine_item",
        "no_action"
    ],
    "dossiers": [{
        "dossierId": "REPLAY-DOSSIER-001",
        "partition": "stable_core",
        "receivedAt": "2026-10-31T10:00:00Z",
        "mailbox": "test@example.com",
        "objective": "Classify this informational email.",
        "sources": [{
            "sourceId": "REPLAY-SOURCE-001",
            "kind": "email",
            "provenance": "informational_notice",
            "title": "Office announcement",
            "lines": [{
                "lineId": "REPLAY-LINE-001",
                "text": "Informational announcement. No action is requested."
            }]
        }]
    }]
}

# First request
first = httpx.post(URL, json=request_data, timeout=60)
print("First request HTTP status:", first.status_code)
print("First response:", first.text[:500])

# Change only the verifier key
request_data["receiptVerifier"]["publicKeyJwk"] = make_jwk()

# Second request using the same evaluation ID
second = httpx.post(URL, json=request_data, timeout=30)
print("Changed request HTTP status:", second.status_code)
print("Second response:", second.text[:500])

print(
    "Replay protection passed:",
    first.status_code == 200 and second.status_code == 409
)