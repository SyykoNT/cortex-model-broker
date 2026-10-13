"""SIWC public-client authentication; no access to other applications' stores."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
import urllib.parse
import urllib.request
import uuid

import jwt

ISSUER = "https://auth.openai.com"
AUTHORIZE = ISSUER + "/api/accounts/authorize"
TOKEN = ISSUER + "/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
DIRECT = "chatgpt.tokens.use.direct"


class AuthError(Exception):
    """Safe code only: never include provider bodies or token values."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuthError("unexpected_upstream_redirect")


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def fetch_json(url, form=None):
    request = urllib.request.Request(url)
    if form is not None:
        request.data = urllib.parse.urlencode(form).encode()
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with HTTP.open(request, timeout=30) as response:
            return json.loads(response.read(2_000_001))
    except Exception:
        raise AuthError("provider_request_failed") from None


def trusted_endpoint(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.netloc != "auth.openai.com" or p.fragment:
        raise AuthError("untrusted_oidc_endpoint")
    return url


class Store:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        s = self.root.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise AuthError("unsafe_state_directory")

    def path(self, name):
        if not name or "/" in name or name.startswith("."):
            raise AuthError("invalid_state_name")
        return self.root / name

    def read(self, name, default=None):
        try:
            fd = os.open(self.path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return default
        with os.fdopen(fd) as f:
            s = os.fstat(f.fileno())
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                    or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or s.st_size > 2_000_000):
                raise AuthError("unsafe_state_file")
            return json.load(f)

    def write(self, name, value):
        # The caller holds the store lock. Private directory excludes other UIDs.
        dest = self.path(name)
        if dest.exists() or dest.is_symlink():
            self.read(name)
        tmp = self.path("write-" + secrets.token_hex(16))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
        directory = os.open(self.root, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextlib.contextmanager
    def lock(self):
        fd = os.open(self.path("auth.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1:
                raise AuthError("unsafe_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


class Auth:
    def __init__(self, store, redirect_uri, get_json=fetch_json):
        self.store, self.redirect_uri, self.get_json = store, redirect_uri, get_json
        p = urllib.parse.urlsplit(redirect_uri)
        if p.scheme != "http" or p.hostname != "127.0.0.1" or p.path != "/auth/callback" or p.query or p.fragment:
            raise AuthError("invalid_callback_uri")
        with store.lock():
            host = store.read("host.json")
            if host is None:
                host = {"ext_agent_host_id": "urn:uuid:" + str(uuid.uuid4())}
                store.write("host.json", host)
            u = uuid.UUID(host["ext_agent_host_id"])
            if u.version != 4 or host["ext_agent_host_id"] != u.urn:
                raise AuthError("invalid_host_id")
            self.host_id = host["ext_agent_host_id"]

    def begin(self, account=None):
        with self.store.lock():
            accounts = self.store.read("accounts.json", {})
            if account is not None and account not in accounts:
                raise AuthError("unknown_account")
            selected = accounts.get(account)
            recovery = self.store.read("registration-recovery.json") if account is None else None
            pending = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
                       "verifier": secrets.token_urlsafe(64), "created": time.time(),
                       "client_id": selected["client_id"] if selected else (recovery["client_id"] if recovery else "dynamic_agent_client"),
                       "account": account, "redirect_uri": self.redirect_uri}
            self.store.write("pending.json", pending)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(pending["verifier"].encode()).digest()).decode().rstrip("=")
            params = {"client_id": pending["client_id"], "ext_agent_host_id": self.host_id,
                      "response_type": "code", "redirect_uri": self.redirect_uri,
                      "scope": SCOPE, "resource": RESOURCE, "state": pending["state"],
                      "nonce": pending["nonce"], "code_challenge_method": "S256", "code_challenge": challenge}
            if selected:
                if selected.get("id_token"):
                    params["id_token_hint"] = selected["id_token"]
            elif pending["client_id"] == "dynamic_agent_client":
                params["agent_name_hint"] = "Cortex Model Broker"
            return AUTHORIZE + "?" + urllib.parse.urlencode(params)

    def validate_id(self, token, client_id, nonce):
        discovery = self.get_json(ISSUER + "/.well-known/openid-configuration")
        if discovery.get("issuer") != ISSUER:
            raise AuthError("issuer_discovery_mismatch")
        jwks = self.get_json(trusted_endpoint(discovery["jwks_uri"]))
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise AuthError("unsupported_id_algorithm")
            keys = [k for k in jwks["keys"] if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"]
            if len(keys) != 1:
                raise AuthError("id_key_not_unique")
            claims = jwt.decode(token, jwt.PyJWK.from_dict(keys[0]).key, algorithms=["RS256"],
                                audience=client_id, issuer=ISSUER,
                                options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]})
            if not secrets.compare_digest(claims["nonce"], nonce):
                raise AuthError("nonce_mismatch")
            if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and claims.get("azp") != client_id:
                raise AuthError("authorized_party_mismatch")
            return claims
        except AuthError:
            raise
        except Exception:
            raise AuthError("id_token_invalid") from None

    def token_record(self, response, previous=None):
        previous = previous or {}
        scopes = response.get("scope")
        scopes = scopes.split() if isinstance(scopes, str) else previous.get("scopes", [])
        if DIRECT not in scopes:
            raise AuthError("plan_scope_not_granted")
        for field in ("access_token", "refresh_token"):
            if not isinstance(response.get(field), str) or not response[field]:
                raise AuthError("incomplete_token_response")
        if str(response.get("token_type", "")).lower() != "bearer":
            raise AuthError("invalid_token_type")
        expiry = response.get("expires_in")
        if type(expiry) is not int or expiry <= 0:
            raise AuthError("invalid_expiry")
        return {**previous, "access_token": response["access_token"], "refresh_token": response["refresh_token"],
                "id_token": response.get("id_token", previous.get("id_token")), "scopes": scopes,
                "expires_at": time.time() + expiry, "saved_at": time.time(),
                "earliest_refresh_at": response.get("earliest_refresh_at"), "token_type": "Bearer"}

    def callback(self, query):
        with self.store.lock():
            pending = self.store.read("pending.json")
            if not pending or time.time() - pending["created"] > 600:
                raise AuthError("no_current_attempt")
            if not secrets.compare_digest(query.get("state", ""), pending["state"]):
                raise AuthError("state_mismatch")
            # Consume before exchange; ambiguous exchanges are not automatically retried.
            self.store.write("pending.json", None)
            if "error" in query:
                raise AuthError("consent_not_completed")
            client = query.get("client_id", pending["client_id"])
            if not client or client == "dynamic_agent_client":
                raise AuthError("registration_incomplete")
            if pending["client_id"] != "dynamic_agent_client" and client != pending["client_id"]:
                raise AuthError("client_id_mismatch")
            if not query.get("code"):
                raise AuthError("missing_code")
            if pending["account"] is None:
                self.store.write("registration-recovery.json", {"client_id": client})
            response = self.get_json(TOKEN, {"grant_type": "authorization_code", "client_id": client,
                "code": query["code"], "code_verifier": pending["verifier"],
                "redirect_uri": pending["redirect_uri"], "resource": RESOURCE})
            claims = self.validate_id(response.get("id_token", ""), client, pending["nonce"])
            accounts = self.store.read("accounts.json", {})
            old = accounts.get(pending["account"])
            if old and (old["subject"] != claims["sub"] or old["client_id"] != client):
                raise AuthError("account_identity_changed")
            record = self.token_record(response)
            record.update(client_id=client, subject=claims["sub"], email=claims.get("email", ""),
                          issuer=ISSUER, ext_agent_host_id=self.host_id, refresh_count=0)
            key = hashlib.sha256((client + "\0" + claims["sub"]).encode()).hexdigest()
            accounts[key] = record
            self.store.write("accounts.json", accounts)
            self.store.write("active.json", {"account": key})
            self.store.write("registration-recovery.json", None)
            return {"account": key, "plan_scope": True}

    def access(self, force_refresh=False):
        with self.store.lock():
            active = self.store.read("active.json")
            if not active:
                raise AuthError("sign_in_required")
            accounts = self.store.read("accounts.json", {})
            record = accounts[active["account"]]
            if DIRECT not in record["scopes"] or not record.get("access_token"):
                raise AuthError("plan_scope_not_granted")
            if force_refresh or time.time() >= record["expires_at"] - 90:
                earliest = record.get("earliest_refresh_at")
                if earliest is not None:
                    try:
                        if time.time() < float(earliest):
                            raise AuthError("refresh_not_yet_allowed")
                    except (TypeError, ValueError):
                        raise AuthError("unknown_refresh_time_format") from None
                response = self.get_json(TOKEN, {"grant_type": "refresh_token", "client_id": record["client_id"],
                    "refresh_token": record["refresh_token"], "resource": RESOURCE})
                record = self.token_record(response, record)
                record["refresh_count"] = record.get("refresh_count", 0) + 1
                accounts[active["account"]] = record
                self.store.write("accounts.json", accounts)
            return record["access_token"]

    def accounts(self):
        with self.store.lock():
            active = self.store.read("active.json", {}) or {}
            records = self.store.read("accounts.json", {})
            return [{"account": k, "label": v["email"] or "ChatGPT account", "client_id": v["client_id"],
                     "active": active.get("account") == k, "refresh_count": v.get("refresh_count", 0)}
                    for k, v in records.items()]

    def revoke(self):
        with self.store.lock():
            active = self.store.read("active.json")
            if not active:
                return
            accounts = self.store.read("accounts.json", {})
            record = accounts[active["account"]]
            discovery = self.get_json(ISSUER + "/.well-known/openid-configuration")
            endpoint = trusted_endpoint(discovery["revocation_endpoint"])
            data = urllib.parse.urlencode({"token": record["refresh_token"], "token_type_hint": "refresh_token",
                                           "client_id": record["client_id"]}).encode()
            try:
                with HTTP.open(urllib.request.Request(endpoint, data=data), timeout=30) as response:
                    if response.status != 200:
                        raise AuthError("revocation_unconfirmed")
            except Exception:
                raise AuthError("revocation_unconfirmed") from None
            for field in ("access_token", "refresh_token", "id_token"):
                record[field] = None
            self.store.write("accounts.json", accounts)
            self.store.write("active.json", None)
