
import base64
import copy
import uuid
import httpx

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


URL = "http://127.0.0.1:8000/v1/mailroom/actions"


# Generate a valid Ed25519 public key.
key = Ed25519PrivateKey.generate()

public_bytes = key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw,
)

public_x = (
    base64.urlsafe_b64encode(public_bytes)
    .rstrip(b"=")
    .decode("ascii")
)


# Base request: a valid request that should pass schema validation.
BASE_REQUEST = {
    "profile": "ga5-mailroom-action-gate/v2",
    "operation": "propose",
    "evaluationId": "VALIDATION-TEST-" + uuid.uuid4().hex,
    "receiptVerifier": {
        "algorithm": "Ed25519",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_x,
        },
    },
    "corpus": {
        "coreId": "validation-core",
        "auditId": "validation-audit",
        "stableCount": 1,
        "freshCount": 0,
    },
    "allowedActions": [
        "create_draft",
        "update_internal_record",
        "send_approved_notice",
        "request_confirmation",
        "quarantine_item",
        "no_action",
    ],
    "dossiers": [
        {
            "dossierId": "VALIDATION-DOSSIER-001",
            "partition": "stable_core",
            "receivedAt": "2026-10-31T10:00:00Z",
            "mailbox": "support@example.com",
            "objective": "Validate request security.",
            "sources": [
                {
                    "sourceId": "VALIDATION-SOURCE-001",
                    "kind": "email",
                    "provenance": "untrusted_external_sender",
                    "title": "Validation test email",
                    "lines": [
                        {
                            "lineId": "VALIDATION-LINE-001",
                            "text": "This is a validation test.",
                        }
                    ],
                }
            ],
        }
    ],
}


# Each test must be rejected before AI processing.
tests = []


# 1. Missing required field.
data = copy.deepcopy(BASE_REQUEST)
del data["dossiers"][0]["objective"]
tests.append(("Missing required field", data))


# 2. Unexpected top-level field.
data = copy.deepcopy(BASE_REQUEST)
data["unexpectedField"] = "not allowed"
tests.append(("Unexpected field", data))


# 3. Duplicate dossier ID.
data = copy.deepcopy(BASE_REQUEST)
duplicate = copy.deepcopy(data["dossiers"][0])
data["dossiers"].append(duplicate)
data["corpus"]["stableCount"] = 2
tests.append(("Duplicate dossier ID", data))


# 4. Incorrect corpus count.
data = copy.deepcopy(BASE_REQUEST)
data["corpus"]["stableCount"] = 2
tests.append(("Incorrect corpus count", data))


# 5. Invalid Ed25519 public key.
data = copy.deepcopy(BASE_REQUEST)
data["receiptVerifier"]["publicKeyJwk"]["x"] = "abc"
tests.append(("Invalid public key", data))


# 6. Duplicate source line ID.
data = copy.deepcopy(BASE_REQUEST)
duplicate_line = copy.deepcopy(
    data["dossiers"][0]["sources"][0]["lines"][0]
)
data["dossiers"][0]["sources"][0]["lines"].append(duplicate_line)
tests.append(("Duplicate source line ID", data))


# 7. Invalid timestamp.
data = copy.deepcopy(BASE_REQUEST)
data["dossiers"][0]["receivedAt"] = "not-a-date"
tests.append(("Invalid timestamp", data))


# 8. Missing timezone in timestamp.
data = copy.deepcopy(BASE_REQUEST)
data["dossiers"][0]["receivedAt"] = "2026-10-31T10:00:00"
tests.append(("Timestamp without timezone", data))


# Run all tests.
all_passed = True

print("STARTING MALFORMED REQUEST TESTS\n")

with httpx.Client(timeout=10.0) as client:

    for name, payload in tests:

        try:
            response = client.post(URL, json=payload)

            passed = response.status_code == 422

            if not passed:
                all_passed = False

            print(
                f"{name}: "
                f"HTTP {response.status_code} "
                f"| {'PASSED' if passed else 'FAILED'}"
            )

            if not passed:
                print("Response:", response.text[:500])

        except Exception as exc:
            all_passed = False
            print(f"{name}: ERROR - {exc}")


print("\n========== FINAL RESULTS ==========")

print("Total tests:", len(tests))
print("All malformed requests rejected:", all_passed)

if all_passed:
    print("\nALL VALIDATION TESTS PASSED!")
else:
    print("\nSOME VALIDATION TESTS FAILED!")

