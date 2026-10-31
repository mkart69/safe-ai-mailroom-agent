import hashlib
import json
from typing import Any

def canonical_json(value: Any) -> str:
    """Recursive key-sorted compact JSON, preserving array order."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

def sha256_hex(value: Any) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else canonical_json(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def proposal_view(proposal: dict) -> dict:
    evidence = sorted(proposal["evidence"])
    return {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": evidence,
    }

def proposal_digest(proposal: dict) -> str:
    return sha256_hex(proposal_view(proposal))
