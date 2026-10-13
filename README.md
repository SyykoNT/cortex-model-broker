# Cortex Model Broker

MIT-licensed, independently registered **Sign in with ChatGPT** public client
and subscription-only Responses transport. This is an early implementation,
not a claim of a production-accepted worker platform.

## Working now

* Loopback setup UI with **Continue with ChatGPT** and a saved-account picker.
* Native dynamic registration, a persisted per-host UUIDv4 URN, PKCE, state,
  nonce and signed ID-token validation against OpenAI OIDC discovery/JWKS.
* Own issued client IDs; no reading, copying or refreshing another client's
  credentials. Required `chatgpt.tokens.use.direct` scope is enforced.
* Owner-only atomic token storage and locked, rotating refresh. Confirmed
  refresh-token revocation retains account/client mappings for reauthorization.
* Responses preview adapter; model/reasoning-bound expiring request-cap keys;
  SSE reconstruction; capture-first provider transport and gitleaks redaction.

## Setup

Python 3.11+ and uv are required. Tested with Python 3.14.

```sh
uv venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m cortex_broker.setup --state ./state --port 18741
```

Open `http://127.0.0.1:18741/` in the browser **on the same host**. Press
**Continue with ChatGPT**. Authorize the requested ChatGPT plan permission.
The first successful callback issues this app's own client ID; no developer
API key or preexisting client ID is required. Keep `state/` private and do
not move its host ID to a different host.

The setup server deliberately has **no inference endpoint**. It refuses
worker calls with HTTP 503. Completing sign-in does not activate workers.

Open <https://chatgpt.com/settings/usage> to inspect the app's actual controls,
set a weekly plan limit and disable credits after plan limits. This software
does not invent app-specific deep links or claim to verify those controls.
No API-key, alternative-provider or alternative-model fallback exists.

## Integration status and limitations

`traffic.Transport` is an exercised library, not an exposed production service.
The deployment must still connect its real proxy/orchestrator health checks,
Unix admin socket, HTTP endpoint, audit-flag notifications and trace export.
The setup service does not claim these integrations are live. It also does not
start any agent, container, scheduler, Claude lane or Grok lane.

Transport buffering preserves the original upstream SSE bytes but delays
consumer delivery until capture completes. A gitleaks hit redacts that whole
captured body rather than publishing a partial secret. Partial streams remain
failed/interrupted and never become successful inference. The 64 MB capture
bound fails closed. Production streaming latency, run cancellation races,
redaction fixtures and provider account acceptance still need deployment tests.

An unavailable model or reasoning level must be reported, never substituted.
Offline fixtures do not demonstrate model availability or a live refresh.

## Official flow references

* [Open-source app authorization](https://developers.openai.com/siwc/token-sharing-open-source)
* [Registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
* [Accounts, refresh and revocation](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
* [Models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
* [Preview limits](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)

## Security

Never report tokens, authorization URLs with ID-token hints, callback query
strings, state files or private transcripts in public issues. Provider errors
are reduced to safe codes. The loopback listener validates Host, Origin and a
CSRF value; it is not an Internet-facing web application. Run it as a dedicated
non-login account with its own private state. Local processes in the same host
trust domain can access the setup UI; deploy network controls accordingly.
