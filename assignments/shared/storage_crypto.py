from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import ChaCha20_Poly1305


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _serialize_aad(aad_obj: dict[str, Any] | None) -> bytes:
    return json.dumps(
        aad_obj or {},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_key_meta() -> dict[str, Any]:
    # TODO [A2]: return the key-derivation metadata for this user.
    # Keep the same fields in the returned row:
    # version, kdf, kdf_params, salt_b64, and key_version.
    # In this scaffold, key_version stays fixed at 1.
    return {
        "version": "a2/v1",
        "kdf": "argon2id",
        "kdf_params": {"t": 3, "m": 65536, "p": 1},
        "salt_b64": _b64e(secrets.token_bytes(16)),
        "key_version": 1,
    }


@dataclass
class StorageCipher:
    key_b64: str

    @classmethod
    def from_password(cls, password: str, key_meta: dict[str, Any]) -> "StorageCipher":
        # TODO [A2]: derive a 256-bit storage key from password + key_meta using a
        # secure password KDF, then return a StorageCipher that holds that derived key.
        # The same password + same metadata must produce the same key every time.
        salt_b64 = str(key_meta.get("salt_b64") or "")
        salt = _b64d(salt_b64)
        params = key_meta.get("kdf_params") or {}
        
        key_raw = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=params.get("t", 3),
            memory_cost=params.get("m", 65536),
            parallelism=params.get("p", 1),
            hash_len=32,
            type=Type.ID,
        )
        return cls(key_b64=_b64e(key_raw))

    @classmethod
    def from_derived_key(cls, key_b64: str) -> "StorageCipher":
        # Runtime helper: rebuild the object from key material already stored in Flask session.
        return cls(key_b64=key_b64)

    def encrypt_body(self, plaintext: str, aad_obj: dict[str, Any] | None = None) -> dict[str, Any]:
        # TODO [A2]: AEAD-encrypt plaintext using self.key_b64 and authenticate aad_obj.
        # Keep this envelope shape stable so the database rows and debug pages stay readable:
        # version, alg, key_version, nonce_b64, ct_b64, tag_b64, aad.
        # Keep aad in the envelope for visibility/debugging, but authenticate the
        # caller-provided aad_obj itself.
        key = _b64d(self.key_b64)
        nonce = secrets.token_bytes(12)
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        aad_bytes = _serialize_aad(aad_obj)
        cipher.update(aad_bytes)
        
        ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        
        return {
            "version": "a2/v1",
            "alg": "chacha20-poly1305",
            "key_version": 1,
            "nonce_b64": _b64e(nonce),
            "ct_b64": _b64e(ct),
            "tag_b64": _b64e(tag),
            "aad": aad_obj or {},
        }

    def decrypt_body(self, envelope: dict[str, Any], aad_obj: dict[str, Any] | None = None) -> str:
        # TODO [A2]: AEAD-decrypt and authenticate the envelope with aad_obj.
        # Reconstruct and authenticate the caller-provided aad_obj instead of trusting
        # envelope["aad"] as the source of truth.
        # Fail closed on wrong key, tampering, malformed input, or mismatched AAD.
        key = _b64d(self.key_b64)
        nonce = _b64d(str(envelope.get("nonce_b64", "")))
        ct = _b64d(str(envelope.get("ct_b64", "")))
        tag = _b64d(str(envelope.get("tag_b64", "")))
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        aad_bytes = _serialize_aad(aad_obj)
        cipher.update(aad_bytes)
        
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode("utf-8")
