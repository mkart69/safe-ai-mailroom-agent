
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("AI_BASE_URL").rstrip("/") + "/chat/completions"

response = httpx.post(
    url,
    headers={
        "Authorization": f"Bearer {os.getenv('AI_API_KEY')}",
        "Content-Type": "application/json",
    },
    json={
        "model": os.getenv("AI_MODEL"),
        "messages": [
            {"role": "user", "content": "Reply with exactly: OK"}
        ],
    },
    timeout=20,
)

print("Model:", os.getenv("AI_MODEL"))
print("HTTP status:", response.status_code)
print("Response:", response.text[:1500])

