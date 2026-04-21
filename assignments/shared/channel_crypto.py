from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client_app.pinned_keys import load_pinned_server_signing_public_key_pem
from server_app.signing_keys import load_server_signing_private_key_pem


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _stable_json(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _gen_p256_keypair() -> tuple[str, str]:
    """Return (priv_der_b64, pub_der_b64) for a fresh P-256 keypair."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64e(priv_der), _b64e(pub_der)


def _ecdh(priv_der_b64: str, peer_pub_der_b64: str) -> bytes:
    priv = serialization.load_der_private_key(_b64d(priv_der_b64), password=None)
    peer_pub = serialization.load_der_public_key(_b64d(peer_pub_der_b64))
    return priv.exchange(ec.ECDH(), peer_pub)  # type: ignore[arg-type]


def _derive_session_keys(
    shared_secret: bytes,
    nonce_c: bytes,
    nonce_s: bytes,
    session_id_bytes: bytes,
) -> tuple[str, str]:
    salt = nonce_c + nonce_s
    k_c2s = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"a3/v1/c2s/" + session_id_bytes,
    ).derive(shared_secret)
    k_s2c = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"a3/v1/s2c/" + session_id_bytes,
    ).derive(shared_secret)
    return _b64e(k_c2s), _b64e(k_s2c)


@dataclass
class ChannelSessionState:
    session_id_b64: str
    k_c2s_b64: str
    k_s2c_b64: str
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id_b64": self.session_id_b64,
            "k_c2s_b64": self.k_c2s_b64,
            "k_s2c_b64": self.k_s2c_b64,
            "expires_at": int(self.expires_at),
        }


@dataclass
class ClientHandshake:
    client_eph_priv_b64: str
    client_eph_pub_b64: str
    nonce_c_b64: str
    ts: int

    @classmethod
    def init(cls) -> "ClientHandshake":
        priv_b64, pub_b64 = _gen_p256_keypair()
        return cls(
            client_eph_priv_b64=priv_b64,
            client_eph_pub_b64=pub_b64,
            nonce_c_b64=_b64e(secrets.token_bytes(32)),
            ts=int(time.time()),
        )

    def create_hello(self) -> dict[str, Any]:
        return {
            "proto": "a3/v1",
            "client_eph_pub_b64": self.client_eph_pub_b64,
            "nonce_c_b64": self.nonce_c_b64,
            "ts": int(self.ts),
        }

    def verify_server_hello(self, server_hello: dict[str, Any]) -> bool:
        pinned_pub_pem = load_pinned_server_signing_public_key_pem()
        if str(server_hello.get("proto") or "") != "a3/v1":
            return False
        session_id_b64 = str(server_hello.get("session_id_b64") or "")
        if not session_id_b64:
            return False
        server_ts = int(server_hello.get("server_ts") or 0)
        expires_at = int(server_hello.get("expires_at") or 0)
        if int(self.ts) <= 0 or server_ts <= 0:
            return False
        if expires_at <= server_ts:
            return False
        # Allow up to 5 minutes of clock skew when checking freshness.
        if server_ts + 300 < int(self.ts):
            return False
        sig_b64 = str(server_hello.get("sig_b64") or "")
        if not sig_b64:
            return False
        transcript_obj = {k: v for k, v in server_hello.items() if k != "sig_b64"}
        try:
            pub_key = serialization.load_pem_public_key(pinned_pub_pem)
            pub_key.verify(  # type: ignore[union-attr]
                _b64d(sig_b64),
                _stable_json(transcript_obj),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:
            return False
        return True

    def finalize(self, server_hello: dict[str, Any]) -> ChannelSessionState:
        session_id_b64 = str(server_hello["session_id_b64"])
        shared_secret = _ecdh(
            self.client_eph_priv_b64,
            str(server_hello["server_eph_pub_b64"]),
        )
        k_c2s_b64, k_s2c_b64 = _derive_session_keys(
            shared_secret,
            _b64d(self.nonce_c_b64),
            _b64d(str(server_hello["nonce_s_b64"])),
            _b64d(session_id_b64),
        )
        return ChannelSessionState(
            session_id_b64=session_id_b64,
            k_c2s_b64=k_c2s_b64,
            k_s2c_b64=k_s2c_b64,
            expires_at=int(server_hello["expires_at"]),
        )

    def accept_server_hello(self, server_hello: dict[str, Any]) -> ChannelSessionState:
        # Runtime convenience wrapper: first verify ServerHello, then derive session state.
        if not self.verify_server_hello(server_hello):
            raise ValueError("invalid_server_hello")
        return self.finalize(server_hello)


@dataclass
class ServerHandshake:
    server_eph_priv_b64: str
    server_eph_pub_b64: str
    nonce_s_b64: str
    server_ts: int
    session_id_b64: str
    expires_at: int

    @classmethod
    def init(cls) -> "ServerHandshake":
        priv_b64, pub_b64 = _gen_p256_keypair()
        server_ts = int(time.time())
        return cls(
            server_eph_priv_b64=priv_b64,
            server_eph_pub_b64=pub_b64,
            nonce_s_b64=_b64e(secrets.token_bytes(32)),
            server_ts=server_ts,
            session_id_b64=_b64e(secrets.token_bytes(16)),
            expires_at=server_ts + 30 * 60,
        )

    def respond_to_client_hello(self, client_hello: dict[str, Any]) -> dict[str, Any]:
        signing_priv_pem = load_server_signing_private_key_pem()
        if str(client_hello.get("proto") or "") != "a3/v1":
            raise ValueError("protocol_mismatch")
        if int(client_hello.get("ts") or 0) <= 0:
            raise ValueError("missing_client_ts")
        if not str(client_hello.get("client_eph_pub_b64") or ""):
            raise ValueError("missing_client_eph_pub")
        if not str(client_hello.get("nonce_c_b64") or ""):
            raise ValueError("missing_nonce_c")

        # Build unsigned server hello; embed client_hello so the signature binds both sides.
        unsigned = {
            "proto": "a3/v1",
            "server_eph_pub_b64": self.server_eph_pub_b64,
            "nonce_s_b64": self.nonce_s_b64,
            "session_id_b64": self.session_id_b64,
            "server_ts": int(self.server_ts),
            "expires_at": int(self.expires_at),
            "client_hello": client_hello,
        }
        signing_priv = serialization.load_pem_private_key(signing_priv_pem, password=None)
        sig = signing_priv.sign(  # type: ignore[union-attr]
            _stable_json(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )
        return {**unsigned, "sig_b64": _b64e(sig)}

    def finalize(self, client_hello: dict[str, Any]) -> ChannelSessionState:
        if not self.session_id_b64:
            raise ValueError("missing_session_id")
        shared_secret = _ecdh(
            self.server_eph_priv_b64,
            str(client_hello["client_eph_pub_b64"]),
        )
        k_c2s_b64, k_s2c_b64 = _derive_session_keys(
            shared_secret,
            _b64d(str(client_hello["nonce_c_b64"])),
            _b64d(self.nonce_s_b64),
            _b64d(self.session_id_b64),
        )
        return ChannelSessionState(
            session_id_b64=self.session_id_b64,
            k_c2s_b64=k_c2s_b64,
            k_s2c_b64=k_s2c_b64,
            expires_at=int(self.expires_at),
        )

    def handle_client_hello(self, client_hello: dict[str, Any]) -> tuple[dict[str, Any], ChannelSessionState]:
        # Runtime convenience wrapper: process ClientHello, then derive the session state that
        # server_app/channel.py stores for later record processing.
        server_hello = self.respond_to_client_hello(client_hello)
        return server_hello, self.finalize(client_hello)


class ChannelCipher:
    def __init__(self, key_b64: str, session_id_b64: str):
        self.key_b64 = key_b64
        self.session_id_b64 = session_id_b64

    def _aad(self, direction: str, counter: int, path: str) -> bytes:
        return _stable_json({
            "counter": int(counter),
            "dir": direction,
            "path": path,
            "session_id_b64": self.session_id_b64,
        })

    def encrypt_record(
        self,
        direction: str,
        counter: int,
        path: str,
        payload_obj: dict[str, Any],
    ) -> dict[str, Any]:
        key = _b64d(self.key_b64)
        nonce = secrets.token_bytes(12)
        aad = self._aad(direction, counter, path)
        aesgcm = AESGCM(key)
        ct_and_tag = aesgcm.encrypt(nonce, _stable_json(payload_obj), aad)
        ct = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]
        return {
            "proto": "a3/v1",
            "session_id_b64": self.session_id_b64,
            "dir": direction,
            "counter": int(counter),
            "path": path,
            "nonce_b64": _b64e(nonce),
            "ct_b64": _b64e(ct),
            "tag_b64": _b64e(tag),
        }

    def decrypt_record(
        self,
        direction: str,
        expected_counter: int,
        path: str,
        record_obj: dict[str, Any],
    ) -> dict[str, Any]:
        if str(record_obj.get("proto") or "") != "a3/v1":
            raise ValueError("protocol_mismatch")
        if str(record_obj.get("session_id_b64") or "") != self.session_id_b64:
            raise ValueError("session_mismatch")
        if str(record_obj.get("dir") or "") != direction:
            raise ValueError("direction_mismatch")
        if int(record_obj.get("counter", -1)) != int(expected_counter):
            raise ValueError("counter_mismatch")
        if str(record_obj.get("path") or "") != path:
            raise ValueError("path_mismatch")
        key = _b64d(self.key_b64)
        nonce = _b64d(str(record_obj["nonce_b64"]))
        ct = _b64d(str(record_obj["ct_b64"]))
        tag = _b64d(str(record_obj["tag_b64"]))
        aad = self._aad(direction, expected_counter, path)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct + tag, aad)
        return json.loads(plaintext.decode("utf-8"))
