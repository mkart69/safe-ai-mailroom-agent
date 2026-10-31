# Safe AI Mailroom Agent

Starter implementation for the `ga5-mailroom-action-gate/v2` assignment.

## Local setup
1. Create and activate a virtual environment.
2. Install: `py -m pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and configure an AI provider.
4. Run: `py -m uvicorn main:app --reload`
5. Health check: `http://127.0.0.1:8000/health`

The grader endpoint is `POST /v1/mailroom/actions`.

Do not submit the URL until the proposal and commit flows have been tested.
