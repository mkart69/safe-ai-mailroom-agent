
import base64
import uuid
import httpx

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

URL = "http://127.0.0.1:8000/v1/mailroom/actions"
PROFILE = "ga5-mailroom-action-gate/v2"

# Generate one key pair for both evaluations.
private_key = Ed25519PrivateKey.generate()

public_bytes = private_key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw
)

jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": base64.urlsafe_b64encode(public_bytes)
        .rstrip(b"=")
        .decode("ascii")
}

# This dossier will be identical in both evaluations.
dossier = {
    "dossierId": "CACHE-TEST-DOSSIER-001",
    "partition": "stable_core",
    "receivedAt": "2026-10-31T10:00:00Z",
    "mailbox": "cache-test@example.com",
    "objective": "Classify this informational email.",
    "sources": [
        {
            "sourceId": "CACHE-SOURCE-001",
            "kind": "email",
            "provenance": "informational notice",
            "title": "Office announcement",
            "lines": [
                {
                    "lineId": "CACHE-LINE-001",
                    "text": "Informational announcement. No action is requested."
                }
            ]
        }
    ]
}

allowed_actions = [
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action"
]


def send_propose(evaluation_id):

    request_data = {
        "profile": PROFILE,
        "operation": "propose",
        "evaluationId": evaluation_id,

        "receiptVerifier": {
            "algorithm": "Ed25519",
            "publicKeyJwk": jwk
        },

        "corpus": {
            "coreId": "cache-test-core",
            "auditId": "audit-" + evaluation_id,
            "stableCount": 1,
            "freshCount": 0
        },

        "allowedActions": allowed_actions,
        "dossiers": [dossier]
    }

    response = httpx.post(
        URL,
        json=request_data,
        timeout=90
    )

    print("Evaluation:", evaluation_id)
    print("HTTP status:", response.status_code)

    if response.status_code != 200:
        print("Error:", response.text)
        raise SystemExit(1)

    return response.json()["proposals"][0]


# First evaluation.
print("\nSTEP 1: First evaluation")

evaluation_one = "CACHE-EVAL-" + uuid.uuid4().hex

proposal_one = send_propose(evaluation_one)

print("First proposal:", proposal_one)


# Second evaluation with the same dossier.
print("\nSTEP 2: Second evaluation")

evaluation_two = "CACHE-EVAL-" + uuid.uuid4().hex

proposal_two = send_propose(evaluation_two)

print("Second proposal:", proposal_two)


# Compare the decisions.
print("\nSTEP 3: Compare proposals")

same_call_id = (
    proposal_one["callId"] == proposal_two["callId"]
)

same_action = (
    proposal_one["action"] == proposal_two["action"]
)

same_target = (
    proposal_one["target"] == proposal_two["target"]
)

same_payload = (
    proposal_one["payload"] == proposal_two["payload"]
)

same_evidence = (
    proposal_one["evidence"] == proposal_two["evidence"]
)

print("Same callId:", same_call_id)
print("Same action:", same_action)
print("Same target:", same_target)
print("Same payload:", same_payload)
print("Same evidence:", same_evidence)

cache_passed = all([
    same_call_id,
    same_action,
    same_target,
    same_payload,
    same_evidence
])

print("\nStable dossier cache test:", cache_passed)

if cache_passed:
    print("STABLE DOSSIER CACHE TEST PASSED!")
else:
    print("STABLE DOSSIER CACHE TEST FAILED!")
