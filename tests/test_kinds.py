"""Operand extraction.

Extraction coverage is a security parameter: a value we do not recognise is a
value we do not seal. These tests pin both directions -- what must be caught,
and what must not be caught, because over-extraction destroys the readability
that makes sealing usable at all.
"""

from __future__ import annotations

import itertools

import pytest

from idensec.kinds import DEFAULT_KINDS, classify, extract, normalise, resolve_kinds


def kinds_of(text: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in extract(text)]


class TestExtraction:
    def test_extracts_the_common_authority_kinds(self) -> None:
        text = (
            "Mail bob@corp.example, see https://docs.corp.example/guide, "
            "open /etc/passwd, host evil.example.org, acct 12345678901234"
        )
        found = dict(kinds_of(text))
        assert found["email"] == "bob@corp.example"
        assert found["url"] == "https://docs.corp.example/guide"
        assert found["posix_path"] == "/etc/passwd"
        assert found["hostname"] == "evil.example.org"
        assert found["account_number"] == "12345678901234"

    def test_spans_do_not_overlap(self) -> None:
        matches = extract("visit https://docs.corp.example/a and mail bob@corp.example")
        spans = [(m.start, m.end) for m in matches]
        for left, right in itertools.pairwise(spans):
            assert left[1] <= right[0]

    def test_hostname_inside_url_is_not_extracted_twice(self) -> None:
        found = kinds_of("see https://docs.corp.example/guide")
        assert found == [("url", "https://docs.corp.example/guide")]

    def test_hostname_inside_email_is_not_extracted_twice(self) -> None:
        found = kinds_of("mail bob@corp.example now")
        assert found == [("email", "bob@corp.example")]

    @pytest.mark.parametrize(
        "filename", ["report.txt", "main.py", "notes.md", "data.csv", "app.tsx"]
    )
    def test_filenames_are_not_hostnames(self, filename: str) -> None:
        """Without this filter, every code file in a tool result becomes a handle."""
        assert ("hostname", filename) not in kinds_of(f"open the {filename} file")

    def test_url_sheds_sentence_punctuation(self) -> None:
        assert kinds_of("Read https://corp.example/a.") == [
            ("url", "https://corp.example/a")
        ]

    def test_url_keeps_balanced_brackets(self) -> None:
        text = "See https://en.example.org/wiki/Foo_(bar) for detail"
        assert kinds_of(text) == [("url", "https://en.example.org/wiki/Foo_(bar)")]

    def test_bare_digit_runs_are_accounts_not_phones(self) -> None:
        """Priority order matters: an account number misread as a phone number
        would be matched against the wrong parameter kind."""
        assert kinds_of("acct 12345678901234") == [
            ("account_number", "12345678901234")
        ]

    def test_short_paths_are_not_extracted(self) -> None:
        assert kinds_of("the ratio is 3/4 here") == []

    def test_empty_text(self) -> None:
        assert extract("") == []

    def test_unicode_is_not_mangled(self) -> None:
        text = "写信给 bob@corp.example 谢谢"
        assert kinds_of(text) == [("email", "bob@corp.example")]


class TestExtendedKinds:
    """Kinds added after the coverage study measured a 69% recall floor."""

    @pytest.mark.parametrize(
        ("text", "kind", "value"),
        [
            ("Fetch s3://backups/q3.tar now", "url", "s3://backups/q3.tar"),
            (
                "DSN postgres://db.corp.example:5432/app",
                "url",
                "postgres://db.corp.example:5432/app",
            ),
            (
                "Clone git@github.com:acme/repo.git",
                "git_remote",
                "git@github.com:acme/repo.git",
            ),
            ("Bucket arn:aws:s3:::corp-backups holds it", "arn", "arn:aws:s3:::corp-backups"),
            (
                "Mount \\\\fileserver\\share\\docs now",
                "unc_path",
                "\\\\fileserver\\share\\docs",
            ),
            ("Copy ~/.ssh/id_ed25519 over", "posix_path", "~/.ssh/id_ed25519"),
            ("Edit ./config/settings.yml first", "posix_path", "./config/settings.yml"),
            ("Traverse ../../etc/shadow upward", "posix_path", "../../etc/shadow"),
            (
                "Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e address",
                "crypto_address",
                "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            ),
        ],
    )
    def test_extended_forms_are_extracted(self, text: str, kind: str, value: str) -> None:
        assert (kind, value) in kinds_of(text)

    def test_git_remote_claims_the_repository_too(self) -> None:
        """Sealing only the host would leave the repository attacker-chosen."""
        found = dict(kinds_of("Clone git@github.com:acme/repo.git today"))
        assert found.get("git_remote") == "git@github.com:acme/repo.git"
        assert "email" not in found

    def test_ipv4_is_not_extracted_by_default(self) -> None:
        """Registered but opt-in: four dotted decimals are ambiguous with
        version strings, and a missed seal is not a bypass."""
        assert kinds_of("Connect to 192.168.1.10 now") == []

    def test_ipv4_is_available_when_asked_for(self) -> None:
        found = extract("Connect to 192.168.1.10 now", [*DEFAULT_KINDS, "ipv4"])
        assert [(m.kind, m.value) for m in found] == [("ipv4", "192.168.1.10")]

    def test_ipv4_octets_are_range_checked(self) -> None:
        found = extract("Build 2.1.4.300 shipped", [*DEFAULT_KINDS, "ipv4"])
        assert found == []

    @pytest.mark.parametrize(
        "prose",
        [
            "Upgrade from 1.2.3.4 to 1.2.4.0 before the freeze.",
            "Choose and/or decide either way.",
            "The ratio is 3/4 and the split was 60/40.",
            "The C: drive and the D: drive were full.",
        ],
    )
    def test_broadened_patterns_do_not_eat_prose(self, prose: str) -> None:
        assert kinds_of(prose) == []


class TestNormalisation:
    def test_addresses_fold_case(self) -> None:
        assert normalise("email", "BOB@Corp.Example") == "bob@corp.example"

    def test_paths_keep_case(self) -> None:
        """POSIX paths are case-sensitive; folding them would merge distinct files."""
        assert normalise("posix_path", "/Etc/Passwd") == "/Etc/Passwd"

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(KeyError):
            normalise("nonexistent", "x")


class TestClassification:
    def test_whole_value_classification(self) -> None:
        assert classify("bob@corp.example") == "email"
        assert classify("/etc/passwd") == "posix_path"
        assert classify("not an operand at all") is None

    def test_partial_match_does_not_classify(self) -> None:
        assert classify("mail bob@corp.example now") is None


class TestRegistry:
    def test_default_kinds_all_resolve(self) -> None:
        assert len(resolve_kinds(DEFAULT_KINDS)) == len(DEFAULT_KINDS)

    def test_priority_ordering(self) -> None:
        """URL first, then the composite forms that *contain* an address, then
        email. git_remote must outrank email: sealing only the host half of
        git@github.com:acme/repo.git would leave the attacker free to choose
        the repository."""
        ordered = [k.name for k in resolve_kinds()]
        assert ordered[0] == "url"
        assert ordered.index("git_remote") < ordered.index("email")
        assert ordered.index("unc_path") < ordered.index("windows_path")
        # ipv4 is opt-in, so check its ordering against the whole registry:
        # when enabled it must claim a literal before hostname sees it.
        with_ipv4 = [k.name for k in resolve_kinds([*DEFAULT_KINDS, "ipv4"])]
        assert with_ipv4.index("ipv4") < with_ipv4.index("hostname")

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(KeyError, match="unregistered"):
            resolve_kinds(["not_a_kind"])


class TestFoundAgainstRealToolOutput:
    """Defects that seven published MCP servers produced and a synthetic corpus
    never did. Each is a regression test for a specific captured response."""

    @pytest.mark.parametrize(
        "text",
        [
            "role.AUTHORITY and Effect.WRITE",
            "json.dumps(value)",
            "time.time()",
            "pytest.mark.parametrize",
            "noun.endswith(suffix)",
            "contract.effects",
        ],
    )
    def test_dotted_code_identifiers_are_not_hostnames(self, text: str) -> None:
        """The blocklist of file extensions was the wrong shape: anything not
        listed was a hostname, so every line of Python an agent reads was
        sealed. Against real `git show` output this fired 151 times."""
        assert not [m for m in extract(text, DEFAULT_KINDS) if m.kind == "hostname"]

    @pytest.mark.parametrize(
        "text", ["mail ana@corp.example", "see wiki.internal", "https://a.co/x"]
    )
    def test_real_hostnames_still_extract(self, text: str) -> None:
        assert extract(text, DEFAULT_KINDS)

    @pytest.mark.parametrize(
        "name", ["main.py", "notes.md", "build.sh", "server.go", "lib.rs", "app.ts"]
    )
    def test_extensions_that_are_also_cctlds_are_not_hostnames(self, name: str) -> None:
        """`.py` is Paraguay, `.md` Moldova, `.sh` St Helena. Accepting every
        two-letter label as a ccTLD put these straight back."""
        assert not [
            m for m in extract(f"open {name} please", DEFAULT_KINDS)
            if m.kind == "hostname"
        ]

    def test_a_path_does_not_absorb_a_full_stop(self) -> None:
        found = extract("the deploy key at ~/.ssh/id_ed25519.", DEFAULT_KINDS)
        assert [m.value for m in found] == ["~/.ssh/id_ed25519"]

    def test_a_path_that_ends_in_dots_keeps_them(self) -> None:
        """`../..` is a traversal, and a stripper that looped would eat it."""
        found = extract("go up with ../.. first", DEFAULT_KINDS)
        assert [m.value for m in found] == ["../.."]
