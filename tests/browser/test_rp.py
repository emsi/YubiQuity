#!/usr/bin/env python3
"""Prove that the local RP rejects invalid ceremonies independently of browsers."""
import hashlib
import os
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData
from rp import Fixture, encode


class RpTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture().__enter__()
        self.addCleanup(self.fixture.__exit__)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(32)
        self.credential = AttestedCredentialData.create(b"\0" * 16, self.id, ES256.from_cryptography_key(self.key.public_key()))

    def response(self, kind, *, origin=None, challenge=None, rp="localhost", flags=None, username="alice", uv="discouraged", cross_origin=False):
        pending = self.fixture.options(kind, {"username": username, "uv": uv, "discoverable": kind != "register"})
        client = CollectedClientData.create(
            "webauthn.create" if kind == "register" else "webauthn.get",
            challenge or pending["options"]["publicKey"]["challenge"],
            origin or self.fixture.origin, cross_origin=cross_origin,
        )
        flags = (0x41 if kind == "register" else 1) if flags is None else flags
        data = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, 0, self.credential if kind == "register" else b"")
        response = {"requestId": pending["requestId"], "rawId": encode(self.id), "clientDataJSON": encode(client)}
        if kind == "register":
            response["attestationObject"] = encode(AttestationObject.create("none", data, {}))
        else:
            response.update(authenticatorData=encode(data), signature=encode(self.key.sign(data + client.hash, ec.ECDSA(hashes.SHA256()))), userHandle=encode(b"alice"))
        return response

    def test_success_and_one_use_challenges(self):
        registration = self.response("register")
        result = self.fixture.complete("register", registration)
        self.assertEqual(result["user"], "alice")
        with self.assertRaises(ValueError):
            self.fixture.complete("register", registration)
        assertion = self.response("authenticate")
        result = self.fixture.complete("authenticate", assertion)
        self.assertEqual(result["credentialId"], encode(self.id))
        with self.assertRaises(ValueError):
            self.fixture.complete("authenticate", assertion)

    def test_origin_challenge_rp_and_presence_are_verified(self):
        for override in [{"origin": "http://evil.test"}, {"challenge": os.urandom(32)}, {"rp": "evil.test"}, {"flags": 0x40}, {"cross_origin": True}, {"uv": "required"}]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.fixture.complete("register", self.response("register", **override))
        self.fixture.complete("register", self.response("register"))
        for override in [{"origin": "http://evil.test"}, {"challenge": os.urandom(32)}, {"rp": "evil.test"}, {"flags": 0}, {"cross_origin": True}, {"uv": "required"}]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.fixture.complete("authenticate", self.response("authenticate", **override))

    def test_signature_user_and_credential_are_bound(self):
        self.fixture.complete("register", self.response("register"))
        for field, value in [("signature", encode(b"invalid")), ("userHandle", encode(b"bob")), ("userHandle", None), ("rawId", encode(os.urandom(32)))]:
            response = self.response("authenticate")
            response[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.fixture.complete("authenticate", response)

    def test_expiration_and_wrong_operation_consume_challenge(self):
        response = self.response("register")
        with self.assertRaises(ValueError):
            self.fixture.complete("authenticate", response)
        with self.assertRaises(ValueError):
            self.fixture.complete("register", response)
        response = self.response("register")
        item = self.fixture.pending[response["requestId"]]
        self.fixture.pending[response["requestId"]] = (0,) + item[1:]
        with self.assertRaises(ValueError):
            self.fixture.complete("register", response)

    def test_http_rejects_untrusted_host_and_origin(self):
        for headers in [{"Host": "evil.test"}, {"Origin": "http://evil.test"}]:
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                urlopen(Request(self.fixture.origin, headers=headers), timeout=2)
            self.assertEqual(error.exception.code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
