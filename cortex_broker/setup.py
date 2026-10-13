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

    def handle_error(self, request, client_address):
        # Callback request lines contain authorization codes. Never print tracebacks.
        print("setup_request_failed", flush=True)


def make_server(directory, port):
    server = Server(("127.0.0.1", port), Handler)
    actual = server.server_address[1]
    server.origin = f"http://127.0.0.1:{actual}"
    server.auth = Auth(Store(directory), server.origin + "/auth/callback")
    server.csrf = secrets.token_urlsafe(32)
    server.mutation_lock = threading.Lock()
    return server


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
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
    args = parser.parse_args()
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY"):
        if os.environ.get(name):
            raise SystemExit("API-key environment refused")
    server = make_server(args.state, args.port)
    print(f"SIWC setup ready at {server.origin}; worker inference disabled", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
