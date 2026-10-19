"""Loopback-only SIWC setup UI. Worker inference stays unavailable in setup mode."""
import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import secrets
import threading
import urllib.parse

from .auth import Auth, AuthError, Store


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_close(self):
        worker = getattr(self, "worker", None)
        if worker is not None:
            worker.close()
        admin = getattr(self, "admin", None)
        if admin is not None:
            admin.close()
        super().server_close()

    def handle_error(self, request, client_address):
        # Callback request lines contain authorization codes. Never print tracebacks.
        print("setup_request_failed", flush=True)


def make_server(directory, port, *, admin_path=None, admin_uid=None, admin_gid=None,
                transport_factory=None, codex_binary=None, capture_directory=None,
                scanner=None, worker_port=None, worker_host='127.0.0.1',
                pilot_worker_socket=None, pilot_capture_socket=None):
    from pathlib import Path
    import ipaddress
    admin_options = (admin_path, admin_uid, admin_gid)
    if any(v is not None for v in admin_options) and not all(v is not None for v in admin_options):
        raise ValueError('incomplete_admin_configuration')
    if (capture_directory is None) != (scanner is None):
        raise ValueError('incomplete_capture_configuration')
    if capture_directory is not None:
        if admin_path is None or transport_factory is not None:
            raise ValueError('invalid_capture_composition')
        state, capture = Path(directory).absolute(), Path(capture_directory).absolute()
        if state == capture or state in capture.parents or capture in state.parents:
            raise ValueError('state_capture_must_be_separate')
    if (pilot_worker_socket is None) != (pilot_capture_socket is None):
        raise ValueError('incomplete_pilot_configuration')
    if pilot_worker_socket is not None and (capture_directory is None or worker_port is not None):
        raise ValueError('invalid_pilot_configuration')
    if worker_port is not None:
        if capture_directory is None:
            raise ValueError('worker_listener_requires_capture')
        # Numeric IPv4 only. The operator must bind an explicit proxy-reachable
        # interface, never an accidental wildcard. No network discovery or DNS.
        address = ipaddress.IPv4Address(worker_host)
        if address.is_unspecified or address.is_multicast or not 0 <= worker_port <= 65535:
            raise ValueError('invalid_worker_listener')
    elif worker_host != '127.0.0.1':
        raise ValueError('worker_host_requires_port')
    server = Server(("127.0.0.1", port), Handler)
    try:
        actual = server.server_address[1]
        server.origin = f"http://127.0.0.1:{actual}"
        server.auth = Auth(Store(directory), server.origin + "/auth/callback")
        server.csrf = secrets.token_urlsafe(32)
        server.mutation_lock = threading.Lock()
        if admin_path is not None:
            from .admin import AdminServer, Controller
            from .protocol import RunKeys
            from .codex_limits import CodexLimits
            keys = RunKeys()
            transport = transport_factory(server.auth, keys) if transport_factory else None
            if capture_directory is not None:
                from .capture_health import BrokerCapture
                from .traffic import Transport
                capture = BrokerCapture(capture_directory, scanner)
                transport = Transport(server.auth, keys, capture, capture.on_limit)
            codex = CodexLimits(codex_binary, server.auth.store.root) if codex_binary else None
            controller = Controller(server.auth, keys, transport=transport, codex=codex)
            if pilot_worker_socket is not None:
                from .pilot import PilotReadiness, PilotTransport, UnixWorkerServer
                readiness = PilotReadiness(transport.capture, pilot_capture_socket, admin_uid)
                server.worker = UnixWorkerServer(pilot_worker_socket, admin_gid, readiness,
                                                PilotTransport(transport, readiness)).start()
                controller.worker_ready = readiness.worker_ready
            server.admin = AdminServer(admin_path, admin_uid, admin_gid, controller).start()
            if worker_port is not None:
                from .worker import Readiness, WorkerServer
                readiness = Readiness(transport.capture)
                # Admin acceptance Transport is deliberately NOT worker Transport.
                # Its broker-only capture cannot satisfy the all-three gate.
                server.worker = WorkerServer((worker_host, worker_port), readiness).start()
    except Exception:
        server.server_close()
        raise
    return server


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self' https://auth.openai.com; frame-ancestors 'none'; base-uri 'none'")
        super().end_headers()

    def reply(self, code, body, mime="text/html; charset=utf-8"):
        body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def host_ok(self):
        return self.headers.get("Host") == urllib.parse.urlsplit(self.server.origin).netloc

    def do_GET(self):
        if not self.host_ok():
            return self.reply(403, "Invalid host")
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/healthz":
            return self.reply(200, json.dumps({"status": "ok", "mode": "setup", "worker_inference": False}), "application/json")
        if url.path == "/auth/callback":
            try:
                parsed = urllib.parse.parse_qs(url.query, strict_parsing=True, max_num_fields=16)
                if any(len(v) != 1 for v in parsed.values()):
                    raise AuthError("duplicate_callback_parameter")
                self.server.auth.callback({k: v[0] for k, v in parsed.items()})
                self.send_response(303)
                self.send_header("Location", "/connected")
                self.end_headers()
                print("siwc_connected_scope_verified", flush=True)
            except AuthError as e:
                self.reply(400, "Sign-in did not complete: " + html.escape(str(e)) + '. <a href="/">Try a new attempt</a>.')
                print("siwc_callback_refused", flush=True)
            except Exception:
                self.reply(400, 'Sign-in did not complete. <a href="/">Try a new attempt</a>.')
                print("siwc_callback_failed", flush=True)
            return
        if url.path not in {"/", "/connected"}:
            return self.reply(404, "Not found")
        accounts = self.server.auth.accounts()
        body = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Cortex Model Broker</title><h1>Cortex Model Broker</h1>'
        body += '<p>Independent Sign in with ChatGPT registration. No other application login is read or copied. Worker inference is disabled during setup.</p>'
        if url.path == "/connected":
            body += '<p>Connected. Required ChatGPT plan scope verified. No model request has been sent.</p><p><a href="https://chatgpt.com/settings/usage">Open ChatGPT Settings → Usage</a>. Select this app and set its weekly plan limit to 70%; turn off credits after plan limits. The broker cannot verify those UI settings automatically.</p>'
        for account in accounts:
            body += '<p>' + html.escape(account["label"]) + ' — ' + html.escape(account["client_id"]) + (' (active)' if account["active"] else '') + '</p>'
            body += self.form(account["account"], "Continue with saved ChatGPT account")
        body += self.form("", "Continue with ChatGPT")
        body += '</html>'
        self.reply(200, body)

    def form(self, account, label):
        return ('<form method="post" action="/auth/start"><input type="hidden" name="csrf" value="' + self.server.csrf + '"><input type="hidden" name="account" value="' + html.escape(account) + '"><button type="submit">' + label + '</button></form>')

    def do_POST(self):
        if not self.host_ok() or self.headers.get("Origin") != self.server.origin:
            return self.reply(403, "Invalid origin")
        if self.path != "/auth/start":
            return self.reply(503, "Worker inference is disabled; setup endpoint only")
        if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            return self.reply(415, "Form required")
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 4096 or self.headers.get("Transfer-Encoding"):
                raise ValueError()
            data = urllib.parse.parse_qs(self.rfile.read(size).decode(), keep_blank_values=True, max_num_fields=4)
            if any(len(v) != 1 for v in data.values()) or not secrets.compare_digest(data.get("csrf", [""])[0], self.server.csrf):
                return self.reply(403, "Invalid form")
            location = self.server.auth.begin(data.get("account", [""])[0] or None)
            self.send_response(303)
            self.send_header("Location", location)
            self.end_headers()
        except (ValueError, AuthError):
            self.reply(400, "Unable to start sign-in")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--port", type=int, default=18741)
    parser.add_argument("--admin-socket")
    parser.add_argument("--admin-uid", type=int, help="Only this kernel peer UID may administer")
    parser.add_argument("--admin-gid", type=int, help="Restrictive socket group")
    parser.add_argument("--codex-binary", help="Optional trusted absolute Codex executable")
    parser.add_argument("--capture-directory", help="Prepared absolute broker-owned capture directory")
    parser.add_argument("--gitleaks", help="Trusted absolute gitleaks executable (required with capture)")
    parser.add_argument("--worker-port", type=int, help="Separate worker listener; admission remains disabled")
    parser.add_argument("--worker-host", default='127.0.0.1', help="Explicit numeric IPv4 bind address, never wildcard")
    parser.add_argument("--pilot-worker-socket", help="Supervised network-none worker UDS")
    parser.add_argument("--pilot-capture-socket", help="Live orchestrator capture transaction socket")
    args = parser.parse_args()
    admin_options = (args.admin_socket, args.admin_uid, args.admin_gid)
    if any(v is not None for v in admin_options) and not all(v is not None for v in admin_options):
        parser.error("admin socket, UID and GID must be configured together")
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY"):
        if os.environ.get(name):
            raise SystemExit("API-key environment refused")
    try:
        server = make_server(args.state, args.port, admin_path=args.admin_socket,
                             admin_uid=args.admin_uid, admin_gid=args.admin_gid, codex_binary=args.codex_binary,
                             capture_directory=args.capture_directory, scanner=args.gitleaks,
                             worker_port=args.worker_port, worker_host=args.worker_host,
                             pilot_worker_socket=args.pilot_worker_socket, pilot_capture_socket=args.pilot_capture_socket)
    except Exception:
        raise SystemExit("setup_start_failed") from None
    import signal
    def terminate(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    worker = getattr(server, 'worker', None)
    listener = f'; worker listener at http://{worker.authority}' if worker else ''
    print(f"SIWC setup ready at {server.origin}; worker inference disabled{listener}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
