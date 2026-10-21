#!/usr/bin/env python3
"""Local-only WebAuthn RP fixture with independent python-fido2 verification.

In-memory registrations persist between ceremonies for this fixture's lifetime.
No production or public accounts are used. Bind to localhost only.
"""
import base64
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time

from fido2.server import Fido2Server
from fido2.webauthn import AttestationObject, AuthenticatorData, CollectedClientData
from fido2 import features

# This fixture explicitly performs binary-to-JSON conversion for distro fido2 1.x.
features.webauthn_json_mapping.enabled = False


def encode(value):
    if isinstance(value, bytes):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")
    if isinstance(value, Mapping):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [encode(item) for item in value]
    return value


def decode(value):
    if not isinstance(value, str) or len(value) > 65536:
        raise ValueError("invalid base64 field")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


class Fixture:
    def __init__(self):
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.fixture = self
        self.origin = f"http://localhost:{self.http.server_port}"
        self.server = Fido2Server({"id": "localhost", "name": "YubiQuity test RP"},
                                  attestation="none", verify_origin=lambda origin: origin == self.origin)
        self.pending = {}
        self.credentials = {}
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def options(self, kind, body):
        now = time.monotonic()
        self.pending = {key: value for key, value in self.pending.items() if value[0] > now}
        if len(self.pending) >= 64 or len(self.credentials) >= 256:
            raise ValueError("fixture capacity exceeded")
        uv = body.get("uv", "discouraged")
        if uv not in ("discouraged", "preferred", "required"):
            raise ValueError("invalid user verification setting")
        username = body.get("username", "alice")
        if not isinstance(username, str) or not username.isascii() or not username.isalnum() or not 1 <= len(username) <= 32:
            raise ValueError("invalid fixture username")
        user_id = username.encode()
        if kind == "register":
            credentials = [credential for credential, owner in self.credentials.values() if owner == user_id]
            options, state = self.server.register_begin(
                {"id": user_id, "name": username, "displayName": username.title()}, credentials,
                resident_key_requirement="required" if body.get("resident", False) else "discouraged",
                user_verification=uv, authenticator_attachment="cross-platform",
            )
            eligible = None
        else:
            discoverable = bool(body.get("discoverable", False))
            eligible = [credential for credential, owner in self.credentials.values() if discoverable or owner == user_id]
            options, state = self.server.authenticate_begin(
                None if discoverable else eligible, user_verification=uv,
            )
        token = secrets.token_urlsafe(24)
        self.pending[token] = (now + 120, kind, user_id, state, eligible, bool(body.get("discoverable", False)))
        return {"requestId": token, "options": encode(options)}

    def complete(self, kind, body):
        item = self.pending.pop(body["requestId"], None)
        if item is None or item[0] < time.monotonic() or item[1] != kind:
            raise ValueError("unknown, replayed, expired or mismatched challenge")
        _, _, user_id, state, eligible, discoverable = item
        client = CollectedClientData(decode(body["clientDataJSON"]))
        if client.cross_origin:
            raise ValueError("cross-origin ceremonies are not allowed in this fixture")
        raw_id = decode(body["rawId"])
        if kind == "register":
            attestation = AttestationObject(decode(body["attestationObject"]))
            data = self.server.register_complete(state, client, attestation)
            credential = data.credential_data
            if credential is None or credential.credential_id != raw_id or credential.public_key.get(3) != -7:
                raise ValueError("credential ID or algorithm mismatch")
            if raw_id in self.credentials:
                raise ValueError("duplicate credential ID")
            self.credentials[raw_id] = (credential, user_id)
            return {"ok": True, "user": user_id.decode(), "credentialId": encode(raw_id), "flags": int(data.flags), "fmt": attestation.fmt}
        data = AuthenticatorData(decode(body["authenticatorData"]))
        credential = self.server.authenticate_complete(
            state, eligible, raw_id, client, data, decode(body["signature"]),
        )
        owner = self.credentials[credential.credential_id][1]
        user_handle = body.get("userHandle")
        if (discoverable and user_handle is None) or (user_handle is not None and decode(user_handle) != owner):
            raise ValueError("assertion user handle mismatch")
        return {"ok": True, "user": owner.decode(), "credentialId": encode(raw_id), "flags": int(data.flags)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def allowed(self):
        expected = f"localhost:{self.server.server_port}"
        return self.headers.get("Host") == expected and self.headers.get("Origin", self.server.fixture.origin) == self.server.fixture.origin

    def respond(self, code, body, content_type="application/json"):
        if content_type == "application/json":
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.allowed():
            self.respond(403, {"error": "invalid host/origin"})
        elif self.path == "/":
            self.respond(200, Path(__file__).with_name("rp.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self.respond(404, {"error": "not found"})

    def do_POST(self):
        try:
            if not self.allowed() or self.headers.get("Content-Type") != "application/json":
                self.respond(403, {"error": "invalid host/origin/content type"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("invalid request size")
            body = json.loads(self.rfile.read(length))
            route = self.path.strip("/").split("/")
            if len(route) != 2 or route[0] not in ("register", "authenticate") or route[1] not in ("options", "complete"):
                self.respond(404, {"error": "not found"})
                return
            with self.server.fixture.lock:
                function = self.server.fixture.options if route[1] == "options" else self.server.fixture.complete
                result = function(route[0], body)
            self.respond(200, result)
        except (ValueError, KeyError, TypeError) as error:
            self.respond(400, {"error": str(error)})


if __name__ == "__main__":
    with Fixture() as fixture:
        print(fixture.origin, flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
