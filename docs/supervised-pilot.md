# Supervised network-none pilot

The optional paired `--pilot-worker-socket` and `--pilot-capture-socket` arguments
compose a dedicated worker Unix socket with the real broker transport. They do
not alter the setup UI or enable the ordinary TCP worker listener.

Workers use network=none. Only the worker socket is mounted; the admin and
controller capture sockets are never mounted. A container-local byte relay
exposes this one endpoint to the native client. Every run has its own capability,
model/reasoning binding, expiry and request cap.

Before admission and before response delivery, the broker asks the authenticated
controller peer for a synchronous capture transaction. It must fsync stdout,
append/fsync an orchestrator event and retain/fsync the current diff. A nonce and
run binding prohibit stale replay. Missing, malformed or failed capture denies
inference. The controller also stops the container on local capture failure.

This is supervised-only: it does not implement the later registry/web proxy,
quota login, dashboard, unattended recovery or negative GitHub tests.
