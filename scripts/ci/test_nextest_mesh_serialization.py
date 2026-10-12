#!/usr/bin/env python3
"""#1283: daemon-mesh binaries stay in the quic-localhost serial group.

The groups job's issue #321 acceptance selector runs three daemon-mesh tests
from `delegation_spaces` in one nextest invocation. nextest runs each test as
its own process, so the binary's in-process suite lock cannot serialise them;
without a `quic-localhost` group override all three pairs form simultaneously
inside the single loopback network namespace the isolated runtime grants the
invocation. Run 37898362740 (issue #1283) lost two of those three meshes.
This test pins the override so the serialization cannot be silently dropped.

The guard validates the EFFECTIVE assignment, not the file text: it parses
only active (uncommented) keys, evaluates each `[[profile.default.overrides]]`
filter expression against the binary, and applies nextest's first-match rule
(the first override whose filter matches a test supplies its settings — see
the ordering note in `.config/nextest.toml`), requiring that override's
`test-group` to be `quic-localhost`. Substring checks are not enough: a
commented-out `test-group` line still contains the string "quic-localhost",
and a negated `not binary(...)` filter still contains `binary(...)` — both
mutations kept an earlier substring guard green (#1283 review). The negative
controls at the bottom of this file reject exactly those mutations.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".config" / "nextest.toml"

# Daemon-mesh binaries that a CI selector runs with more than one test per
# nextest invocation. Single-test selectors gain nothing from the group, so
# they are deliberately absent (see the module docstring in the config).
SERIALIZED_MESH_BINARIES = ("delegation_spaces",)

OVERRIDES_HEADER = "[[profile.default.overrides]]"
GROUP_TABLE = "[test-groups.quic-localhost]"


class ConfigError(Exception):
    """The nextest config cannot be validated as written (fail closed)."""


@dataclass(frozen=True)
class Override:
    filter: str
    test_group: str | None
    filter_line: int
    group_line: int | None


def _toml_string(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    raise ConfigError(f"expected a quoted TOML string, got {raw!r}")


def parse_overrides(text: str) -> list[Override]:
    """Parse `[[profile.default.overrides]]` blocks from ACTIVE lines only.

    A commented-out key or header is not configuration — nextest never sees
    it, so the guard must not either. Every block must carry an active
    `filter` (nextest rejects an override without one); anything else fails
    closed via ConfigError.
    """
    lines = text.splitlines()
    overrides: list[Override] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() != OVERRIDES_HEADER:
            i += 1
            continue
        i += 1
        values: dict[str, tuple[str, int]] = {}
        while i < len(lines):
            stripped = lines[i].strip()
            if stripped.startswith("["):
                break
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, _, raw = stripped.partition("=")
                key = key.strip()
                if key in ("filter", "test-group"):
                    if key in values:
                        # TOML rejects duplicate keys in one table; nextest
                        # would never accept this file, so neither does the
                        # guard. This also catches a commented-out block
                        # header leaking its keys into the previous block.
                        raise ConfigError(
                            f"duplicate active key {key!r} in override block "
                            f"around line {i + 1}"
                        )
                    values[key] = (_toml_string(raw), i)
            i += 1
        if "filter" not in values:
            raise ConfigError(
                f"override block ending at line {i} has no active filter key"
            )
        overrides.append(
            Override(
                filter=values["filter"][0],
                test_group=values["test-group"][0] if "test-group" in values else None,
                filter_line=values["filter"][1],
                group_line=values["test-group"][1] if "test-group" in values else None,
            )
        )
    return overrides


def evaluate_filter(expression: str, binary: str) -> bool:
    """Evaluate a nextest filter expression for `binary`.

    Answers: would this override select any test of `binary`? Supported
    grammar (everything `.config/nextest.toml` uses today): `binary(name)`,
    `test(...)`, `all()`, `not`, `and`/`&`, `or`/`|`, parentheses.
    `test(...)` matches test NAMES, which this file-only guard cannot know
    without building the workspace; it evaluates False, which can only make
    the guard miss a shadowing test-name override — never pass a broken
    config. Any other construct raises ConfigError so the guard fails
    closed and gets taught the new syntax.
    """
    pos = 0

    def skip_ws() -> None:
        nonlocal pos
        while pos < len(expression) and expression[pos].isspace():
            pos += 1

    def peek() -> str | None:
        skip_ws()
        return expression[pos] if pos < len(expression) else None

    def take(char: str) -> None:
        nonlocal pos
        skip_ws()
        if pos < len(expression) and expression[pos] == char:
            pos += 1
        else:
            raise ConfigError(
                f"expected {char!r} at offset {pos} in filter {expression!r}"
            )

    def ident() -> str:
        nonlocal pos
        skip_ws()
        start = pos
        while pos < len(expression) and (
            expression[pos].isalnum() or expression[pos] in "_-"
        ):
            pos += 1
        if start == pos:
            raise ConfigError(
                f"expected identifier at offset {pos} in filter {expression!r}"
            )
        return expression[start:pos]

    def maybe_ident() -> str | None:
        nxt = peek()
        if nxt is None or not (nxt.isalpha() or nxt == "_"):
            return None
        return ident()

    def unary() -> bool:
        nonlocal pos
        saved = maybe_ident()
        if saved == "not":
            return not unary()
        if saved is not None:
            pos -= len(saved)  # put the identifier back for primary()
        return primary()

    def and_expr() -> bool:
        nonlocal pos
        value = unary()
        while True:
            skip_ws()
            if pos < len(expression) and expression[pos] == "&":
                pos += 1
            elif maybe_ident() == "and":
                pass
            else:
                return value
            value = unary() and value

    def or_expr() -> bool:
        nonlocal pos
        value = and_expr()
        while True:
            skip_ws()
            if pos < len(expression) and expression[pos] == "|":
                pos += 1
            elif maybe_ident() == "or":
                pass
            else:
                return value
            value = unary() or value

    def argument() -> str:
        nonlocal pos
        take("(")
        start = pos
        while pos < len(expression) and expression[pos] != ")":
            pos += 1
        if pos >= len(expression):
            raise ConfigError(f"unterminated argument in filter {expression!r}")
        arg = expression[start:pos].strip()
        take(")")
        return arg

    def primary() -> bool:
        if peek() == "(":
            take("(")
            value = or_expr()
            take(")")
            return value
        name = ident()
        if name == "all":
            argument()
            return True
        if name == "binary":
            return argument() == binary
        if name == "test":
            argument()
            return False
        raise ConfigError(f"unsupported predicate {name!r} in filter {expression!r}")

    result = or_expr()
    skip_ws()
    if pos != len(expression):
        raise ConfigError(
            f"trailing input at offset {pos} in filter {expression!r}"
        )
    return result


def effective_test_group(text: str, binary: str) -> str | None:
    """The test-group nextest would apply to `binary`'s tests, or None.

    nextest applies the FIRST override whose filter matches; a matching
    override without `test-group` leaves the tests unserialised.
    """
    for override in parse_overrides(text):
        if evaluate_filter(override.filter, binary):
            return override.test_group
    return None


def assert_serialized_in_quic_localhost(text: str, binary: str) -> None:
    group = effective_test_group(text, binary)
    if group != "quic-localhost":
        raise AssertionError(
            f".config/nextest.toml must run {binary} in the quic-localhost "
            f"test-group (#1283); the effective group is {group!r}. The "
            "daemon-mesh selector would otherwise run its pairs concurrently "
            "in one loopback namespace."
        )


def active_key_in_section(text: str, section: str, key: str) -> str | None:
    """Value of an active `key = ...` line inside `section`, else None."""
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == section
            continue
        if not in_section or stripped.startswith("#") or "=" not in stripped:
            continue
        k, _, raw = stripped.partition("=")
        if k.strip() == key:
            return raw.strip()
    return None


def _config_text() -> str:
    return CONFIG.read_text(encoding="utf-8")


def _matching_override(text: str, binary: str) -> Override:
    for override in parse_overrides(text):
        if evaluate_filter(override.filter, binary):
            return override
    raise AssertionError(f"no override matches {binary} in the config under test")


class FilterEvaluation(unittest.TestCase):
    def test_binary_predicate_matches_only_the_named_binary(self) -> None:
        self.assertTrue(evaluate_filter("binary(delegation_spaces)", "delegation_spaces"))
        self.assertFalse(evaluate_filter("binary(other)", "delegation_spaces"))

    def test_negated_binary_does_not_match(self) -> None:
        self.assertFalse(
            evaluate_filter("not binary(delegation_spaces)", "delegation_spaces")
        )

    def test_boolean_operators_and_parentheses(self) -> None:
        self.assertTrue(
            evaluate_filter(
                "binary(a) | binary(delegation_spaces)", "delegation_spaces"
            )
        )
        self.assertFalse(evaluate_filter("binary(a) | binary(b)", "delegation_spaces"))
        self.assertTrue(
            evaluate_filter(
                "not binary(other) & binary(delegation_spaces)", "delegation_spaces"
            )
        )
        self.assertFalse(
            evaluate_filter("binary(a) & binary(delegation_spaces)", "delegation_spaces")
        )
        self.assertTrue(
            evaluate_filter(
                "(binary(a) | binary(b)) & not binary(c) | binary(delegation_spaces)",
                "delegation_spaces",
            )
        )
        self.assertTrue(evaluate_filter("all()", "delegation_spaces"))

    def test_test_predicates_cannot_match_a_binary(self) -> None:
        self.assertFalse(
            evaluate_filter(
                "test(mesh_connections) | test(/^test_local_/)", "delegation_spaces"
            )
        )

    def test_unsupported_or_malformed_filters_fail_closed(self) -> None:
        for bad in ("package(x)", "binary(delegation_spaces", "binary)", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    evaluate_filter(bad, "delegation_spaces")


class EffectiveAssignment(unittest.TestCase):
    def test_mesh_binaries_are_effectively_in_the_quic_localhost_group(self) -> None:
        text = _config_text()
        for binary in SERIALIZED_MESH_BINARIES:
            with self.subTest(binary=binary):
                assert_serialized_in_quic_localhost(text, binary)

    def test_quic_localhost_group_still_serialises(self) -> None:
        # The group only serialises while `max-threads = 1` is an ACTIVE line;
        # a commented `# max-threads = 1` must read as absent.
        self.assertEqual(
            active_key_in_section(_config_text(), GROUP_TABLE, "max-threads"), "1"
        )

    def test_override_without_an_active_filter_is_a_config_error(self) -> None:
        text = (
            f"{OVERRIDES_HEADER}\n"
            "# filter = 'binary(delegation_spaces)'\n"
            'test-group = "quic-localhost"\n'
        )
        with self.assertRaises(ConfigError):
            effective_test_group(text, "delegation_spaces")


class NegativeControls(unittest.TestCase):
    """In-memory mutations that must be rejected (#1283 review).

    Both of the reviewer's reproductions kept the old substring guard
    green: commenting out the group assignment leaves the string
    "quic-localhost" in the file, and negating the filter leaves the
    substring `binary(delegation_spaces)` in the expression.
    """

    def test_commented_out_group_assignment_is_rejected(self) -> None:
        text = _config_text()
        override = _matching_override(text, "delegation_spaces")
        assert override.group_line is not None
        lines = text.splitlines()
        lines[override.group_line] = "# " + lines[override.group_line]
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_negated_filter_is_rejected(self) -> None:
        text = _config_text()
        override = _matching_override(text, "delegation_spaces")
        lines = text.splitlines()
        lines[override.filter_line] = f'filter = "not {override.filter}"'
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_retargeted_group_is_rejected(self) -> None:
        text = _config_text()
        override = _matching_override(text, "delegation_spaces")
        assert override.group_line is not None
        lines = text.splitlines()
        lines[override.group_line] = 'test-group = "membership-cluster"'
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_earlier_shadowing_override_wins_and_is_rejected(self) -> None:
        # nextest applies the FIRST matching override, so an earlier block
        # without a test-group silently unserialises the binary even though
        # the #1283 block below it is intact.
        text = _config_text()
        lines = text.splitlines()
        first = next(i for i, line in enumerate(lines) if line.strip() == OVERRIDES_HEADER)
        shadow = [
            OVERRIDES_HEADER,
            'filter = "binary(delegation_spaces)"',
            "# test-group deliberately absent",
            "",
        ]
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost(
                "\n".join(lines[:first] + shadow + lines[first:]), "delegation_spaces"
            )

    def test_commented_out_override_header_is_not_config(self) -> None:
        text = _config_text()
        override = _matching_override(text, "delegation_spaces")
        lines = text.splitlines()
        # Walk back to the block's header line and comment it out: the
        # override stops existing for nextest, and its keys leak into the
        # previous block as duplicates — invalid TOML — so the guard must
        # reject the file either way (AssertionError or ConfigError).
        header = override.filter_line
        while lines[header].strip() != OVERRIDES_HEADER:
            header -= 1
        lines[header] = "# " + lines[header]
        with self.assertRaises((AssertionError, ConfigError)):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")


if __name__ == "__main__":
    unittest.main()
