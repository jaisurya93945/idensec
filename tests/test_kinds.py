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
        ordered = resolve_kinds()
        assert [k.name for k in ordered][:2] == ["url", "email"]

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(KeyError, match="unregistered"):
            resolve_kinds(["not_a_kind"])
