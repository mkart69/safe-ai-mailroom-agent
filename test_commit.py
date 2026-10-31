
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

from canonical import canonical_json, proposal_digest


URL = "http://127.0.0.1:8000/v1/mailroom/actions"
PROFILE = "ga5-mailroom-action-gate/v2"


# Generate a temporary Ed25519 key pair.
private_key = Ed25519PrivateKey.generate()

public_bytes = private_key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw
)

public_x = base64.urlsafe_b64encode(
    public_bytes
).rstrip(b"=").decode("ascii")


# Create the public JWK.
jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": public_x
}


# Generate a unique evaluation ID.
evaluation_id = "COMMIT-TEST-" + uuid.uuid4().hex


# Build a sample propose request.
propose_request = {
    "profile": PROFILE,
    "operation": "propose",
    "evaluationId": evaluation_id,

    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": jwk
    },

    "corpus": {
        "coreId": "commit-test-core",
        "auditId": "commit-test-audit",
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

    "dossiers": [
        {
            "dossierId": "COMMIT-DOSSIER-001",
            "partition": "stable_core",
            "receivedAt": "2026-10-31T10:00:00Z",
            "mailbox": "test@example.com",
            "objective": "Classify this informational email.",

            "sources": [
                {
                    "sourceId": "COMMIT-SOURCE-001",
                    "kind": "email",
                    "provenance": "informational notice",
                    "title": "Office announcement",

                    "lines": [
                        {
                            "lineId": "COMMIT-LINE-001",
                            "text": "Informational announcement. No action is requested."
                        }
                    ]
                }
            ]
        }
    ]
}


# STEP 1: Submit the propose request.
print("\nSTEP 1: Sending propose request...")

propose_response = httpx.post(
    URL,
    json=propose_request,
    timeout=90
)

print("Propose HTTP status:", propose_response.status_code)

if propose_response.status_code != 200:
    print("Propose failed:", propose_response.text)
    raise SystemExit(1)

proposed = propose_response.json()

print("Proposal received successfully.")

input_digest = proposed["inputDigest"]
proposal = proposed["proposals"][0]


# STEP 2: Calculate the proposal digest.
proposal_hash = proposal_digest(proposal)

print("Proposal action:", proposal["action"])
print("Proposal digest:", proposal_hash)


# STEP 3: Create an unsigned receipt.
receipt = {
    "dossierId": proposal["dossierId"],
    "callId": proposal["callId"],
    "action": proposal["action"],
    "accepted": True,
    "proposalDigest": proposal_hash,
    "receiptId": "receipt-" + uuid.uuid4().hex
}


# Build the exact object that must be signed.
signed_object = {
    "profile": PROFILE,
    "evaluationId": evaluation_id,
    "inputDigest": input_digest,
    "receipt": receipt
}


# Sign the canonical JSON bytes.
signed_bytes = canonical_json(signed_object).encode("utf-8")

signature = private_key.sign(signed_bytes)

receipt["receiptSignature"] = base64.b64encode(
    signature
).decode("ascii")


# STEP 4: Submit the commit request.
commit_request = {
    "profile": PROFILE,
    "operation": "commit",
    "evaluationId": evaluation_id,
    "inputDigest": input_digest,
    "receipts": [receipt]
}

print("\nSTEP 2: Sending signed commit request...")

commit_response = httpx.post(
    URL,
    json=commit_request,
    timeout=30
)

print("Commit HTTP status:", commit_response.status_code)
print("Commit response:", commit_response.text)

if commit_response.status_code != 200:
    print("\nCOMMIT TEST FAILED")
    raise SystemExit(1)

result = commit_response.json()

commit_passed = (
    result.get("status") == "completed"
    and len(result.get("outcomes", [])) == 1
    and result["outcomes"][0].get("status") == "executed"
)

print("\nValid receipt commit passed:", commit_passed)


# STEP 5: Replay the exact same commit.
print("\nSTEP 3: Testing exact commit replay...")

replay_response = httpx.post(
    URL,
    json=commit_request,
    timeout=30
)

print("Exact replay HTTP status:", replay_response.status_code)

exact_replay_passed = (
    replay_response.status_code == 200
    and replay_response.json() == result
)

print("Exact commit replay passed:", exact_replay_passed)


# STEP 6: Change the receipt ID and attempt a modified replay.
print("\nSTEP 4: Testing altered commit replay...")

altered_request = {
    **commit_request,
    "receipts": [
        {
            **receipt,
            "receiptId": "receipt-altered-" + uuid.uuid4().hex
        }
    ]
}

altered_response = httpx.post(
    URL,
    json=altered_request,
    timeout=30
)

print("Altered replay HTTP status:", altered_response.status_code)

altered_replay_passed = (
    altered_response.status_code == 409
)

print("Altered commit replay rejected:", altered_replay_passed)


# Final result.
print("\n========== FINAL TEST RESULTS ==========")
print("Valid receipt commit:", commit_passed)
print("Exact replay:", exact_replay_passed)
print("Altered replay rejection:", altered_replay_passed)

if (
    commit_passed
    and exact_replay_passed
    and altered_replay_passed
):
    print("\nALL COMMIT TESTS PASSED!")
else:
    print("\nONE OR MORE COMMIT TESTS FAILED.")
