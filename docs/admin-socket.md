# Linux admin socket (protocol version 1)

This is an operator control channel, **not a worker or lead-agent model route**.
The setup HTTP server's Host, Origin, CSRF and authorization checks are unchanged.
No new HTTP admin endpoint is added. Enabling the socket does not enable worker
HTTP inference or certify live provider acceptance.

## Deployment boundary

Run the service as the dedicated broker-service identity. An administrator must
prepare a short absolute runtime directory owned by that identity, mode `0750`,
with a restrictive group containing the authorized operator identity. The
socket owner is the **actual service EUID**, never a name supplied in a request;
its group is the configured numeric GID and its mode is exactly `0660`.
Broker state remains separately owner-only (`0700` directory / `0600` files).
Workers must not have group membership, path access or this socket mounted.

All ancestors must be directories owned by root or the service identity, without
symlinks or group/world write. The immediate parent must be service-owned. The
service does not create users/groups, change unrelated ownership, grant sudo,
clean stale sockets, or silently replace existing files. A private staging
socket is restricted **before** publication with a non-overwriting hard link.
Shutdown removes only the original inode. Same-UID fixture tests do not prove
host broker-service/authorized-operator separation or container network isolation.

Startup arguments (numeric identities are illustrative, not an installation):

```sh
python -m cortex_broker.setup --state /var/lib/model-broker/state --port 18741 \
  --admin-socket /run/model-broker/admin.sock --admin-uid 2001 --admin-gid 2001 \
  --capture-directory /var/log/model-broker/admin --gitleaks /opt/model-broker/bin/gitleaks \
  --worker-host 127.0.0.1 --worker-port 18742
```

The three admin arguments are all-or-none. Omitting them preserves setup-only
startup. A bad path, owner, mode, group assignment or existing node fails startup.
The service uses kernel `SO_PEERCRED` and permits exactly `--admin-uid`, in addition
to the filesystem ACL. The client verifies the socket mode/owner and kernel
server UID; overflow UID/GID 65534 is refused. Preserve host identity mappings;
do not relax peer checks to make a remapped namespace pass.

### Deployable broker-only acceptance capture

`--capture-directory` and `--gitleaks` are all-or-none and require the admin
socket. They compose the **actual** `traffic.Transport` with the setup server's
own `Auth` and `RunKeys`; no Python factory or environment override is needed.
Omitting both preserves the old status/revoke-only control channel. Capture and
state must be separate, non-nested directories.

Prepare the absolute capture directory in advance, service-owned, mode `0750`
(or `0700`), with protected ancestors as above. Use a log-reader group only if
needed; do not make it worker-writable. The service does not chown or repair an
unsafe installation. Existing captures must be owner-owned regular files with
one link, no symlinks, no group write and no world permissions (`0640` or `0600`).
Install real gitleaks at an absolute regular executable path, owned by root or
the service identity, without group/world write or symlink ancestors. Python
3.11+ and `requirements.txt` are required; no new Python dependency is added.
Keep executable code and scanner configuration under the service's trust boundary.

Startup and each capture append perform a **fresh broker-only** health probe:
scanner accepts clean input and detects an in-memory synthetic canary, protected
path/identity checks, fresh-file creation, write + file fsync + directory fsync + exact readback,
then unlink + directory fsync. A bounded transient `.capture-probe-*` file contains
only a random nonsecret probe; normal completion removes it. It is not a
proxy/orchestrator heartbeat or an acceptance certificate. Each real run
append separately validates its file and fsyncs the file and directory; unsafe
files/FIFOs cannot hang or redirect a capture write. Failure prevents dispatch;
post-dispatch capture failure prevents response delivery/success. Scanner probes
have a five-second deadline per invocation; actual record scanning retains the
30-second limit. Health results are not cached as permission to dispatch.

**Scope choice:** the all-three requirement in the governing PRD §9.2 and A1.1
is explicitly for **worker runs/model traffic**. Fixed, peer-checked operator
acceptance (`models`, the bounded `infer` and `tool_probe`, `refresh`, `reconstruct`, optional
`rate_limits`) is not worker traffic and needs actual **broker** capture, not
invented proxy/orchestrator events. This separation breaks the acceptance startup
cycle without relaxing the worker gate. An observed admin usage limit is captured
as `admin.usage_limit`; it does not claim an orchestrator pause or alert.

Admin success never certifies FC2/FC5 as a whole or enables worker minting. A
fixed-prompt reconstruction checks that one capture, not a full tool-bearing
Hermes run compared with session export. Live provider acceptance, trace export,
archive handoff, redaction alerts and actual proxy/orchestrator integration remain
deployment work. `mint` continues to refuse `worker_admission_disabled`.

### Separate worker HTTP listener

`--worker-port` optionally starts a separate bounded, serial HTTP listener; it
requires the capture configuration above. It does **not** change setup's Handler,
Host, Origin or CSRF checks. Its default bind address is `127.0.0.1`; a deployment
may specify one explicit numeric IPv4 address with `--worker-host`. Wildcard and
multicast binds are refused. Configure the proxy to preserve the listener's
numeric `Host: address:port`; firewall the port so only the proxy can reach it.
This code does not install firewall rules or prove container isolation.

In the shipped CLI:
- `GET /healthz` returns **503**, `worker_inference:false`, the real
  `broker_capture` result and explicit missing-integration/acceptance reasons.
- `POST /v1/responses` and `GET /v1/models` return **503**, even after successful
  admin acceptance and with an arbitrary bearer key.
- No setup, OAuth or admin route exists on this listener. Browser Origins and
  wrong/duplicate Hosts are refused; no CORS support is added.
- No enable-worker flag, acceptance marker, forged heartbeat or constant-true
  callback exists. The admin broker-only Transport is **never** installed as the
  worker Transport, and the CLI never supplies a worker-ready mint callback.

The worker adapter is separately tested offline with explicitly synthetic
all-three readiness and acceptance: bearer per-run bounds, strict bounded JSON
and HTTP framing, full capture before original buffered SSE delivery, quota
pass-through, revocation/refusal capture, and acceptance-key exclusion. Its
catalog lists only the approved model bound to an active worker key, never an
unauthenticated provider catalog. Those positive fixtures do not establish a
live worker service. Production wiring must use actual proxy logging and
orchestrator-event health plus the existing A1.1 acceptance results before
supplying worker transport/admission. Those producers are not implemented here;
unknown readiness stays unavailable, rather than trusting an operator-written
`ready` file. This is a remaining implementation requirement, not an additional
approval gate.

The worker adapter bounds headers with Python's HTTP parser, body size at 8 MB,
backlog at eight and absolute header/body ingress at three seconds (also a
three-second connection inactivity timeout); requests are serial
and connections close after one request. Upstream size/deadline limits are those
of `Transport` below. The listener is not designed as an Internet-facing server.

## Wire format and client

One UTF-8 JSON object plus newline, then **write-half EOF**, per connection. No
pipelining, duplicate fields, unknown fields, nonfinite numbers or extra payload.
Requests are limited to 16 KiB, responses to 64 KiB. Ingress has an absolute
3-second deadline; writes have a 3-second timeout. The listener handles requests
serially with a backlog of eight, not one unbounded thread per connection.
The client has a 300-second response deadline; a timeout is an unknown outcome,
not authorization to replay a state-changing command. Capture/refresh/network
operations have their own size/deadline/lock limits. Network read deadlines are
checked between chunks, with the socket's timeout bounding a blocked read.
Shutdown waits up to 300 seconds for the current operation; if it cannot finish,
it raises `admin_shutdown_incomplete` and retains the node rather than reporting
successful teardown or publishing a second authority.

```sh
printf '%s\n' '{"version":1,"command":"status"}' |
  python -m cortex_broker.admin --socket /run/model-broker/admin.sock --broker-uid 2000
```

The CLI emits one safe JSON response and exits zero only on `ok:true`.
Responses are `{"ok":true,"result":{...}}` or
`{"ok":false,"error":"fixed_safe_code"}`. Never print exception details, provider
error bodies, stderr, environment or session files to diagnose a refusal.

Every command requires `version:1` and `command`; **only** the listed extra fields
are accepted:

| Command | Extra fields | Behavior |
|---|---|---|
| `status` | none | Metadata-only session projection: scopes, `client_id`, `ext_agent_host_id`, expiry, refresh count and `last_refresh_at`. No network/implicit refresh. No access, refresh or ID token. Historical sessions without a recorded refresh timestamp return null. Setup worker inference remains false. |
| `models` | none | Existing `Transport.models`; only visible validated model slugs returned. No model availability fabricated. |
| `infer` | `model`, `reasoning` | Exactly `gpt-6.1-sol` and `medium` or `high`; one call using a one-request internal acceptance key, fixed user text `Say exactly: Hello, world!`, no tools, `store:false`, `stream:true`. No fallback/retry. Key revoked in `finally`. |
| `tool_probe` | none | Fixed FC5 operation: exactly two streamed `gpt-6.1-sol` high requests, one fixed harmless function, full context and one linked function output on the second request. No caller prompt, tools, model, reasoning, URL, path or budget. Returns only a closed replay summary, never arbitrary model text. |
| `refresh` | none | Existing `Auth.access(force_refresh=True)`, under the shared bounded refresh lock. Returns metadata only; no caller token or path accepted. |
| `reconstruct` | `run_id` | Bounded no-follow read of that run's retained JSONL, not caller-supplied paths; validates request/upstream association, exact model/effort, raw SSE against stored reconstruction, terminal completion and integer token usage. Refuses incomplete, changed, redacted or flagged records. |
| `rate_limits` | none | Optional documented Codex app-server integration below. No quota inferred from ordinary API errors. |
| `mint` | `run_id`, `role`, `model`, `reasoning`, `expires_at`, `cap` | Requires separate worker-admission and capture prerequisites. Existing role/model/effort allowlists and two-hour expiry bound; integer cap 1–10000. Returns one ephemeral per-run capability, never a provider token. Bound-request refusals are captured without the key. |
| `revoke` | `run_id` | Revokes all in-process capabilities for the run; remains available when capture is down. No capability survives restart. |

Successful inference returns terminal event, exact model/effort, integer input and
output usage, and a reread reconstruction result. Raw output and provider bodies
stay in redacted capture, not the admin reply. Only a single final
`response.completed` qualifies; missing usage, mismatched model, interrupted
streams, trailing events and failed/incomplete responses do not. Effort is the
exact request value; if the provider also returns reasoning metadata, a mismatch
is refused. Missing provider reasoning metadata is not proof of effective effort. Redaction or
capture-write failure cannot be presented as a successful reconstruction.
This checks consistency, **not cryptographic archive authenticity** against a
malicious service owner who can rewrite every copy. Trace export remains a
separate deployment prerequisite.

## Fixed tool-bearing FC5 operation

The exact packet is `{"version":1,"command":"tool_probe"}`. Existing infer,
status, refresh and client attempt semantics are unchanged. The fixed function
`functions.fc5_fixed_marker` accepts only `{"probe":"fc5"}` (strict closed
object schema, required singleton-enum string) and returns exactly the JSON string
`{"marker":"fc5-fixed-ok"}`. It performs no I/O, shell, URL fetch or general tool
dispatch. The model must issue exactly one completed `function_call` with that
name/namespace and arguments; missing, extra, malformed or other calls fail.
First request uses `tool_choice:"required"`, second `"none"`, both disable
parallel calls and use `store:false`, `stream:true`. Existing adaptation groups
the fixed function into the `functions` namespace. Both requests include
`reasoning.encrypted_content`; all first-response output items are copied into
the second full `input`, followed by the literal `function_call_output` bearing
the exact model-returned `call_id`. The final assistant message must be `FC5_OK`.

The broker mints only an internal acceptance key with cap two, revokes it in
`finally`, and never retries. It uses the existing Transport, actual scanner and
Capture. It reads back and validates the first capture plus `tool.result` before
the second request, and the complete retained run before reporting success.
Both responses require exact model, explicit high reasoning echo, final completion,
valid integer usage and streamed item/argument identities consistent with terminal
output. Model incompatibility is a refusal, never model or effort substitution.

Cold reconstruction validates an exact ordered nine-record sequence, two unique
transport call IDs, acceptance admission/cap/used fields, fixed request bytes as
JSON values, exact adaptations, original SSE bytes/count/classification/reparsed
data, model function call, constant local result and identical full-input
correspondence. A deleted opening marker does not downgrade a tool transcript
to legacy tool-less replay. Summary fields are `run_id`, `verified_calls:2`,
`calls` (per-request model/effort/terminal/usage), `tool` (fixed name, arguments,
output and validated model call ID) and `final_text:"FC5_OK"`. The operation
wraps this as `{run_id, reasoning:"high", reconstruction}`. Raw transcripts
remain in broker capture; the admin reply cannot export arbitrary model text.
This proves consistency against the fixed contract, not cryptographic authenticity
against a broker owner capable of replacing every transcript.

Live FC5 has not been established by offline fixtures. A later actual fixed run
can establish tool-bearing broker-log reconstruction on this route; it does not
claim a full Hermes worker/session export, proxy/orchestrator integration or
enable workers. The separate listener/admission remains OFF.

### Secret-safe scanner diagnostics (not recovery)

Gitleaks reports are requested as JSON on stdout, read only through bounded pipes
and memory (4 MB, 30 seconds, at most 4096 findings), never saved or printed.
Successful no-match captures keep their existing schema and values. On a detected
match, the entire value is still replaced by `redacted_body:"gitleaks-match"`,
with `flags:["secret"]` and a `gitleaks` redaction. Only `scanner_diagnostics`
is added: version, total finding count, rule IDs, per-rule counts and numeric
start/end line/column locations. Locations refer to the scanner's JSON input
after pre-redaction, not necessarily the original SSE body. No Secret, Match,
context, path, value or complete raw report may be retained or returned.

Missing, malformed, inconsistent, oversized or timed-out reports are scanner
failures, not accepted redactions; no success is synthesized. No scanner
exclusions, allowlists or disabled detection were added. Diagnostics do **not**
make redacted captures reconstructable and cannot retroactively recover a prior
discarded raw body/header. A match alone does not establish a true secret or a
false positive. Reconstruction continues to reject every flagged/redacted row.

## D1: documented Codex app-server quota read

Optional trusted service configuration: `--codex-binary /absolute/native/codex`.
This must name an executable regular file (not a symlink) owned by root or the
service owner, without group/world write, under protected ancestors. The RPC
caller cannot choose the executable, arguments, environment, path or method.
The service does **not** install or launch Claude, start a Codex inference thread,
read an existing Codex login, run a shell, or call undocumented quota URLs.

The child uses a fresh temporary `HOME`, `CODEX_HOME`, `TMPDIR` and working
directory, no inherited provider credentials/proxy settings, and only the broker's
SIWC access token in `ACCESS_TOKEN`. The fixed provider configuration is:

```toml
model_provider = "openai_chatgpt_plan"
[model_providers.openai_chatgpt_plan]
name = "ChatGPT plan"
base_url = "https://api.openai.com/v1"
env_key = "ACCESS_TOKEN"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
```

Documented stdio sequence: `initialize` → `initialized` →
`account/rateLimits/read`. No `account/login/start` or `thread/start`. There is a
15-second deadline, 256 KiB cumulative output limit, strict request IDs, at most
32 notifications, dropped stderr and process-group cleanup. Only validated numeric
`primary` / `secondary` rate-limit windows are returned; arbitrary account data,
credit fields, strings and messages are not relayed.

A Codex version/custom-provider combination may **not support** quota reads for
this auth mode. Missing binary, protocol error, deadline or unsupported/unavailable
limits returns an explicit refusal (`codex_unavailable`, `codex_protocol_error`,
`codex_timeout`, `codex_rate_limits_unavailable`). Do not switch to a separate Codex
login or an undocumented backend. Synthetic executable fixtures exercise the
real subprocess/stdio path; they do not prove installed Codex compatibility or a
live account quota. That acceptance remains explicitly unverified.

References:
- [Codex app-server auth endpoints](https://developers.openai.com/codex/app-server)
- [SIWC custom Responses provider](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)

## Offline verification

Use the existing required full suite with real Chromium and gitleaks:

```sh
TEST_CHROMIUM=/absolute/chrome-headless-shell TEST_GITLEAKS=/absolute/gitleaks \
  python -m unittest discover -s tests -v
```

Admin fixtures never open real credential stores or provider endpoints. They
cover kernel peer checks and modes, client subprocess round trips, malformed,
oversize and slow requests, capture outages and scanner/write failures, redaction,
exact requests, terminal/usage refusals, refresh locking and real synthetic
Codex-child handshake/timeout/error cleanup. Browser tests remain mandatory.
