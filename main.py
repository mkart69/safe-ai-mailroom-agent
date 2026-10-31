import json

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from canonical import canonical_json, sha256_hex, proposal_digest
from schemas import PROFILE, ProposeRequest, CommitRequest
from storage import get_session, Evaluation, DecisionCache, StoredReceipt
from decision_engine import (
    decide_dossiers,
    make_call_id,
    validate_model_proposal,
)
from security import verify_receipt, valid_call_id

app = FastAPI(
    title="Safe AI Mailroom Agent",
    version="1.0.0",
)

# The assignment rejects successful request bodies larger than 512 KiB.
# Enforce this while streaming, rather than reading an unbounded body first.
MAX_BODY = 512 * 1024
MAX_RESPONSE = 512 * 1024


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/mailroom/actions")
async def mailroom_actions(request: Request):
    chunks = []
    total_size = 0

    # Content-Length is only an early-rejection optimization.
    # The streaming count below remains authoritative.
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY:
                raise HTTPException(413, "Request body too large")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length header")

    async for chunk in request.stream():
        total_size += len(chunk)

        if total_size > MAX_BODY:
            raise HTTPException(413, "Request body too large")

        chunks.append(chunk)

    raw = b"".join(chunks)

    try:
        data = json.loads(raw)

        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")

        operation = data.get("operation")

        if operation == "propose":
            req = ProposeRequest.model_validate(data)
            return await handle_propose(req)

        if operation == "commit":
            req = CommitRequest.model_validate(data)
            return handle_commit(req)

        raise HTTPException(
            400,
            "operation must be propose or commit"
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            422,
            f"Invalid request: {str(exc)[:300]}"
        )


async def handle_propose(req: ProposeRequest):
    dossiers = [
        d.model_dump(mode="json")
        for d in req.dossiers
    ]

    # Calculate the required input digest.
    input_digest = sha256_hex(dossiers)

    # Fingerprint the complete propose request to detect changed
    # verifier keys or other request content on evaluation replay.
    propose_request_digest = sha256_hex(
        req.model_dump(mode="json")
    )

    verifier = req.receiptVerifier.model_dump(mode="json")

    # First database check: look for an existing evaluation
    # and retrieve previously cached decisions.
    with get_session() as db:
        existing = db.get(
            Evaluation,
            req.evaluationId
        )

        if existing:
            if (
                existing.input_digest != input_digest
                or existing.propose_request_digest
                != propose_request_digest
            ):
                raise HTTPException(
                    409,
                    "evaluationId reused with changed content"
                )

            return JSONResponse(
                json.loads(existing.propose_response)
            )

        fingerprints = {
            d["dossierId"]: sha256_hex(d)
            for d in dossiers
        }

        cached = {}
        missing = []

        for d in dossiers:
            row = db.get(
                DecisionCache,
                fingerprints[d["dossierId"]]
            )

            if row:
                cached[d["dossierId"]] = json.loads(
                    row.proposal_json
                )
            else:
                missing.append(d)

    # Run the decision engine only for dossiers that are not cached.
    if missing:
        try:
            model_items = await decide_dossiers(missing)

            by_id = {
                x.get("dossierId"): x
                for x in model_items
                if isinstance(x, dict)
            }

            expected_ids = {
                d["dossierId"]
                for d in missing
            }

            if (
                len(by_id) != len(missing)
                or set(by_id) != expected_ids
            ):
                raise ValueError(
                    "Model must return exactly one item per uncached dossier"
                )

            for d in missing:
                item = validate_model_proposal(
                    by_id[d["dossierId"]],
                    d
                )
                cached[d["dossierId"]] = item

        except Exception as exc:
            print(
                f"DECISION ENGINE ERROR: "
                f"{type(exc).__name__}: {exc}"
            )

            raise HTTPException(
                503,
                f"Decision engine failed safely: {str(exc)[:250]}"
            )

    # Build exactly one proposal for each dossier.
    proposals = []

    for d in dossiers:
        fingerprint = fingerprints[d["dossierId"]]
        item = cached[d["dossierId"]]

        proposal = {
            "dossierId": d["dossierId"],
            "callId": make_call_id(
                d["dossierId"],
                fingerprint
            ),
            "action": item["action"],
            "target": item["target"],
            "payload": item["payload"],
            "evidence": item["evidence"],
        }

        if not valid_call_id(proposal["callId"]):
            raise HTTPException(
                500,
                "Internal callId generation error"
            )

        proposals.append(proposal)

    response = {
        "profile": PROFILE,
        "evaluationId": req.evaluationId,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }

    encoded = canonical_json(response)

    if len(encoded.encode("utf-8")) > MAX_RESPONSE:
        raise HTTPException(
            413,
            "Response too large"
        )

    # Second database check and transaction:
    # persist the proposals, cache entries and evaluation.
    with get_session() as db:
        existing = db.get(
            Evaluation,
            req.evaluationId
        )

        if existing:
            if (
                existing.input_digest != input_digest
                or existing.propose_request_digest
                != propose_request_digest
            ):
                raise HTTPException(
                    409,
                    "evaluationId reused with changed content"
                )

            return JSONResponse(
                json.loads(existing.propose_response)
            )

        for d in dossiers:
            fingerprint = fingerprints[d["dossierId"]]

            if not db.get(DecisionCache, fingerprint):
                proposal = next(
                    p for p in proposals
                    if p["dossierId"] == d["dossierId"]
                )

                cache_item = {
                    key: proposal[key]
                    for key in (
                        "dossierId",
                        "action",
                        "target",
                        "payload",
                        "evidence",
                    )
                }

                db.add(
                    DecisionCache(
                        fingerprint=fingerprint,
                        dossier_id=d["dossierId"],
                        proposal_json=canonical_json(cache_item),
                    )
                )

        db.add(
            Evaluation(
                evaluation_id=req.evaluationId,
                input_digest=input_digest,
                propose_request_digest=propose_request_digest,
                verifier_jwk=canonical_json(verifier),
                propose_response=encoded,
            )
        )

        db.commit()

    return JSONResponse(response)


def handle_commit(req: CommitRequest):
    with get_session() as db:
        # Find the original evaluation.
        evaluation = db.get(
            Evaluation,
            req.evaluationId
        )

        if not evaluation:
            raise HTTPException(
                409,
                "Unknown evaluation"
            )

        if evaluation.input_digest != req.inputDigest:
            raise HTTPException(
                409,
                "inputDigest does not match evaluation"
            )

        # Calculate a fingerprint of the complete commit request.
        commit_request_digest = sha256_hex(
            req.model_dump(mode="json")
        )

        # Exact replay returns the previously stored response.
        if evaluation.commit_response:
            if (
                evaluation.commit_request_digest
                != commit_request_digest
            ):
                raise HTTPException(
                    409,
                    "evaluationId replayed with changed commit content"
                )

            return JSONResponse(
                json.loads(evaluation.commit_response)
            )

        # Retrieve the proposals persisted during propose.
        proposal_response = json.loads(
            evaluation.propose_response
        )

        expected = {
            p["dossierId"]: p
            for p in proposal_response["proposals"]
        }

        # Require exactly one receipt for every proposal.
        if (
            len(req.receipts) != len(expected)
            or len({
                r.dossierId
                for r in req.receipts
            }) != len(req.receipts)
        ):
            raise HTTPException(
                400,
                "Exactly one unique receipt per proposal is required"
            )

        verifier = json.loads(
            evaluation.verifier_jwk
        )

        outcomes = []
        seen_receipt_ids = set()

        # Verify every receipt before recording any outcome.
        for receipt_model in req.receipts:
            receipt = receipt_model.model_dump(
                mode="json"
            )

            proposal = expected.get(
                receipt["dossierId"]
            )

            if not proposal:
                raise HTTPException(
                    400,
                    "Receipt dossier does not belong to this evaluation"
                )

            if receipt["receiptId"] in seen_receipt_ids:
                raise HTTPException(
                    400,
                    "Duplicate receiptId"
                )

            seen_receipt_ids.add(
                receipt["receiptId"]
            )

            expected_digest = proposal_digest(proposal)

            if (
                receipt["callId"] != proposal["callId"]
                or receipt["action"] != proposal["action"]
                or receipt["proposalDigest"] != expected_digest
            ):
                raise HTTPException(
                    400,
                    "Receipt does not match persisted proposal"
                )

            if not verify_receipt(
                receipt,
                verifier["publicKeyJwk"],
                req.evaluationId,
                req.inputDigest,
            ):
                raise HTTPException(
                    400,
                    "Invalid receipt signature; no actions committed"
                )

            outcomes.append({
                "dossierId": receipt["dossierId"],
                "callId": receipt["callId"],
                "action": receipt["action"],
                "proposalDigest": receipt["proposalDigest"],
                "receiptId": receipt["receiptId"],
                "status": (
                    "executed"
                    if receipt["accepted"] is True
                    else "rejected"
                ),
            })

        response = {
            "profile": PROFILE,
            "evaluationId": req.evaluationId,
            "status": "completed",
            "inputDigest": req.inputDigest,
            "outcomes": outcomes,
        }

        encoded = canonical_json(response)

        if len(encoded.encode("utf-8")) > MAX_RESPONSE:
            raise HTTPException(
                413,
                "Response too large"
            )

        # Store all verified receipts.
        for receipt_model in req.receipts:
            receipt_data = receipt_model.model_dump(
                mode="json"
            )

            db.add(
                StoredReceipt(
                    evaluation_id=req.evaluationId,
                    receipt_id=receipt_data["receiptId"],
                    receipt_json=canonical_json(receipt_data),
                )
            )

        # Persist the commit response for exact replay.
        evaluation.commit_request_digest = (
            commit_request_digest
        )
        evaluation.commit_response = encoded

        db.commit()

        return JSONResponse(response)
