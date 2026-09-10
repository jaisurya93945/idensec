"""Tests for the repository's own security tooling.

The commit verifier is a security gate. A gate that silently passes everything
is worse than no gate, so it gets the same treatment as the library: known
vectors, and negative cases that must fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from _ed25519 import verify
from verify_commits import (
    SignatureError,
    SshSig,
    load_allowed_keys,
    split_commit,
)

# RFC 8032 section 7.1 test vectors.
VECTOR_EMPTY = (
    bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8"
        "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
    b"",
)
VECTOR_ONE_BYTE = (
    bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a"
        "c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ),
    bytes.fromhex("72"),
)


class TestEd25519:
    @pytest.mark.parametrize("vector", [VECTOR_EMPTY, VECTOR_ONE_BYTE])
    def test_rfc8032_vectors_verify(self, vector) -> None:
        public_key, signature, message = vector
        assert verify(public_key, signature, message)

    def test_tampered_message_fails(self) -> None:
        public_key, signature, _ = VECTOR_ONE_BYTE
        assert not verify(public_key, signature, b"\x73")

    def test_tampered_signature_fails(self) -> None:
        public_key, signature, message = VECTOR_ONE_BYTE
        assert not verify(public_key, signature[:-1] + b"\x01", message)

    def test_wrong_key_fails(self) -> None:
        _, signature, message = VECTOR_ONE_BYTE
        assert not verify(VECTOR_EMPTY[0], signature, message)

    def test_non_canonical_scalar_is_rejected(self) -> None:
        """Rejecting s >= L is what stops trivial signature malleability."""
        from _ed25519 import L

        public_key, signature, message = VECTOR_ONE_BYTE
        malleable = signature[:32] + (
            int.from_bytes(signature[32:], "little") + L
        ).to_bytes(32, "little")
        assert not verify(public_key, malleable, message)

    @pytest.mark.parametrize("bad", [b"", b"\x00" * 31, b"\x00" * 33])
    def test_malformed_inputs_are_rejected_not_raised(self, bad: bytes) -> None:
        _, signature, message = VECTOR_ONE_BYTE
        assert not verify(bad, signature, message)


class TestCommitParsing:
    def test_unsigned_commit_is_reported(self) -> None:
        raw = b"tree abc\nauthor a <a@b.example> 0 +0000\n\nsubject\n"
        with pytest.raises(SignatureError, match="not signed"):
            split_commit(raw)

    def test_malformed_object_is_reported(self) -> None:
        with pytest.raises(SignatureError, match="malformed"):
            split_commit(b"no body separator")

    def test_signature_header_is_stripped_from_the_payload(self) -> None:
        raw = (
            b"tree abc\n"
            b"author a <a@b.example> 0 +0000\n"
            b"gpgsig -----BEGIN SSH SIGNATURE-----\n"
            b" AAAA\n"
            b" -----END SSH SIGNATURE-----\n"
            b"committer a <a@b.example> 0 +0000\n"
            b"\nsubject\n"
        )
        payload, armoured = split_commit(raw)
        assert b"gpgsig" not in payload
        assert b"committer" in payload
        assert "AAAA" in armoured

    def test_garbage_signature_is_reported(self) -> None:
        with pytest.raises(SignatureError, match=r"magic|base64"):
            SshSig.parse("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----")


class TestAllowedSigners:
    def test_repository_pins_at_least_one_key(self) -> None:
        allowed = load_allowed_keys(
            Path(__file__).resolve().parent.parent / ".github" / "allowed_signers"
        )
        assert allowed, "the repository must pin the keys permitted to sign it"
        assert all(key.startswith("ssh-") for key in allowed)

    def test_comments_and_blank_lines_are_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "allowed_signers"
        path.write_text(
            "# a comment\n\nana@corp.example namespaces=\"git\" ssh-ed25519 AAAAKEY\n"
        )
        assert load_allowed_keys(path) == {"ssh-ed25519 AAAAKEY": "ana@corp.example"}

    def test_missing_file_is_a_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit, match=r"allowed-signers"):
            load_allowed_keys(tmp_path / "nope")
