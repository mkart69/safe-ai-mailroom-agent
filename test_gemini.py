
import asyncio
from dotenv import load_dotenv
from decision_engine import decide_dossiers

load_dotenv()

test_dossiers = [
    {
        "dossierId": "TEST-001",
        "partition": "stable_core",
        "receivedAt": "2026-10-31T10:00:00Z",
        "mailbox": "test@example.com",
        "objective": "Classify this informational email.",
        "sources": [
            {
                "sourceId": "SRC-001",
                "kind": "email",
                "provenance": "informational_notice",
                "title": "Office announcement",
                "lines": [
                    {
                        "lineId": "LINE-001",
                        "text": "This is an informational announcement. No action is requested."
                    }
                ]
            }
        ]
    }
]

async def main():
    try:
        result = await decide_dossiers(test_dossiers)
        print("GEMINI TEST SUCCESSFUL")
        print(result)
    except Exception as e:
        print("GEMINI TEST FAILED")
        print(type(e).__name__, str(e))

asyncio.run(main())
