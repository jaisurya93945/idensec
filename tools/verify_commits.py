#!/usr/bin/env python3
"""Verify that every commit in a range carries a valid SSH signature.

Written because "commit.gpgsign = true" is a configuration, not a guarantee.
A signer that silently no-ops, a rebase that drops headers, or a key that is
not the one you think it is all produce a repository that *looks* signed. This
checks the actual bytes: it reconstructs each commit's signed payload, parses
the SSHSIG blob out of the ``gpgsig`` header, and verifies the Ed25519
signature against a pinned allowed-signers file.

    python3 tools/verify_commits.py                 # every commit on HEAD
    python3 tools/verify_commits.py origin/main..HEAD
    python3 tools/verify_commits.py --allowed-signers .github/allowed_signers

Exit status is 0 only if every commit in the range verifies against a pinned
key. Standard library only, using the Ed25519 verifier in ``tools/_ed25519.py``:
a check on the integrity of the repository should not itself depend on code
fetched from an index.

Reference: OpenSSH PROTOCOL.sshsig.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ed25519 import verify as ed25519_verify

MAGIC = b"SSHSIG"
DEFAULT_ALLOWED = Path(__file__).resolve().parent.parent / ".github" / "allowed_signers"


class SignatureError(Exception):
    """The signature is absent, malformed, or does not verify."""


def _git() -> str:
    """Resolve git to an absolute path rather than trusting PATH lookup."""
    resolved = shutil.which("git")
    if resolved is None:
        raise SystemExit("git is not on PATH")
    return resolved


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    return data[offset : offset + length], offset + length


@dataclass(frozen=True)
class SshSig:
    public_key: bytes
    namespace: bytes
    hash_algorithm: bytes
    signature: bytes

    @property
    def key_type(self) -> str:
        return _read_string(self.public_key, 0)[0].decode()

    @property
    def authorized_key(self) -> str:
        return f"{self.key_type} {base64.b64encode(self.public_key).decode()}"

    @classmethod
    def parse(cls, armoured: str) -> SshSig:
        body = "".join(
            line for line in armoured.splitlines() if "-----" not in line
        ).strip()
        try:
            blob = base64.b64decode(body)
        except (ValueError, TypeError) as exc:
            raise SignatureError(f"signature is not valid base64: {exc}") from exc
        if not blob.startswith(MAGIC):
            raise SignatureError("missing SSHSIG magic")
        offset = len(MAGIC)
        (version,) = struct.unpack(">I", blob[offset : offset + 4])
        offset += 4
        if version != 1:
            raise SignatureError(f"unsupported SSHSIG version {version}")
        public_key, offset = _read_string(blob, offset)
        namespace, offset = _read_string(blob, offset)
        _reserved, offset = _read_string(blob, offset)
        hash_algorithm, offset = _read_string(blob, offset)
        signature, _ = _read_string(blob, offset)
        return cls(public_key, namespace, hash_algorithm, signature)

    def signed_blob(self, message: bytes) -> bytes:
        """The bytes OpenSSH actually signs: a wrapper around H(message)."""
        algorithm = self.hash_algorithm.decode()
        if algorithm not in {"sha256", "sha512"}:
            raise SignatureError(f"unsupported hash algorithm {algorithm!r}")
        digest = hashlib.new(algorithm, message).digest()
        return b"".join(
            [
                MAGIC,
                struct.pack(">I", len(self.namespace)),
                self.namespace,
                struct.pack(">I", 0),
                struct.pack(">I", len(self.hash_algorithm)),
                self.hash_algorithm,
                struct.pack(">I", len(digest)),
                digest,
            ]
        )

    def verify(self, message: bytes) -> None:
        key_type, offset = _read_string(self.public_key, 0)
        if key_type != b"ssh-ed25519":
            raise SignatureError(
                f"only ssh-ed25519 is supported here, got {key_type.decode()}"
            )
        raw_key, _ = _read_string(self.public_key, offset)
        sig_type, sig_offset = _read_string(self.signature, 0)
        if sig_type != b"ssh-ed25519":
            raise SignatureError(f"signature algorithm mismatch: {sig_type.decode()}")
        raw_signature, _ = _read_string(self.signature, sig_offset)
        if not ed25519_verify(raw_key, raw_signature, self.signed_blob(message)):
            raise SignatureError("signature does not verify")


def split_commit(raw: bytes) -> tuple[bytes, str]:
    """Return the payload OpenSSH signed and the armoured signature.

    Git signs the commit object with the ``gpgsig`` header removed, so the
    header has to be stripped back out byte-for-byte to reconstruct it.
    """
    header, separator, body = raw.partition(b"\n\n")
    if not separator:
        raise SignatureError("malformed commit object")
    kept: list[bytes] = []
    signature: list[bytes] = []
    collecting = False
    for line in header.split(b"\n"):
        if line.startswith(b"gpgsig "):
            collecting = True
            signature.append(line[len(b"gpgsig ") :])
            continue
        if collecting and line.startswith(b" "):
            signature.append(line[1:])
            continue
        collecting = False
        kept.append(line)
    if not signature:
        raise SignatureError("commit is not signed")
    payload = b"\n".join(kept) + b"\n\n" + body
    return payload, b"\n".join(signature).decode()


def load_allowed_keys(path: Path) -> dict[str, str]:
    """Parse an OpenSSH allowed_signers file into {authorized_key: identity}."""
    if not path.exists():
        raise SystemExit(
            f"no allowed-signers file at {path}\n"
            "Create one containing the key(s) permitted to sign this repository, "
            'e.g.:\n  maintainer@example.com namespaces="git" ssh-ed25519 AAAA...'
        )
    allowed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        identity = fields[0]
        for index, field in enumerate(fields):
            if field.startswith("ssh-") or field.startswith("sk-"):
                allowed[" ".join(fields[index : index + 2])] = identity
                break
    return allowed


def commits_in(revision_range: str) -> list[str]:
    # S603: the revision range is a developer-supplied CLI argument, passed as
    # an argv element to an absolute executable path -- there is no shell.
    output = subprocess.run(  # noqa: S603
        [_git(), "rev-list", "--", revision_range]
        if revision_range.startswith("-")
        else [_git(), "rev-list", revision_range],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return output.split()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("range", nargs="?", default="HEAD", help="git revision range")
    parser.add_argument("--allowed-signers", type=Path, default=DEFAULT_ALLOWED)
    args = parser.parse_args()

    allowed = load_allowed_keys(args.allowed_signers)
    failures = 0
    commits = commits_in(args.range)
    if not commits:
        print(f"no commits in range {args.range!r}")
        return 0

    for commit in commits:
        raw = subprocess.run(  # noqa: S603
            [_git(), "cat-file", "commit", commit],
            capture_output=True,
            check=True,
        ).stdout
        subject = raw.partition(b"\n\n")[2].split(b"\n")[0].decode(errors="replace")
        try:
            payload, armoured = split_commit(raw)
            sig = SshSig.parse(armoured)
            sig.verify(payload)
            identity = allowed.get(sig.authorized_key)
            if identity is None:
                raise SignatureError(
                    f"valid signature by an unpinned key: {sig.authorized_key}"
                )
            print(f"OK      {commit[:10]}  {identity:<28} {subject[:56]}")
        except SignatureError as exc:
            failures += 1
            print(f"FAIL    {commit[:10]}  {exc}")
        except subprocess.CalledProcessError as exc:
            failures += 1
            print(f"FAIL    {commit[:10]}  git error: {exc}")

    print(
        f"\n{len(commits) - failures}/{len(commits)} commits verified against "
        f"{args.allowed_signers}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
