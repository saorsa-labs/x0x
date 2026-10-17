#!/usr/bin/env python3
"""#1283: daemon-mesh tests stay in the quic-localhost serial group.

The groups job's issue #321 acceptance selector runs three daemon-mesh tests
from `delegation_spaces` in one nextest invocation. nextest runs each test as
its own process, so the binary's in-process suite lock cannot serialise them;
without a `quic-localhost` group assignment all three pairs form
simultaneously inside the single loopback network namespace the isolated
runtime grants the invocation. Run 37898362740 (issue #1283) lost two of
those three meshes. This test pins the assignment so the serialization cannot
be silently dropped.

The guard validates the EFFECTIVE assignment of every TEST, not the file
text and not the binary as a whole:

* It parses only active (uncommented) keys of `[[profile.default.overrides]]`
  blocks. The acceptance step runs the default profile (no `--profile`), so
  no other profile's overrides are consulted.
* It enumerates the test functions in `tests/delegation_spaces.rs` and
  evaluates each override filter against each test's real identity (package,
  binary, binary id, kind and test name). `test(...)` predicates are
  evaluated with nextest's name matchers, so a filter such as
  `binary(delegation_spaces) & not test(delegation_)` is seen to drop the
  acceptance cases.
* It applies nextest's per-setting precedence: for each test, the first
  override that matches the test AND configures `test-group` supplies the
  group. An override without `test-group` (say, timeout only) is ignored for
  that setting, exactly as nextest ignores it.

Substring checks are not enough: a commented-out `test-group` line still
contains the string "quic-localhost", and a negated `not binary(...)` filter
still contains `binary(...)` (#1283 review). The negative controls at the
bottom of this file reject those mutations and the test-name variants of
them; the positive controls prove that valid configurations still pass.
"""

from __future__ import annotations

import fnmatch
import re
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".config" / "nextest.toml"
INTEGRATION_WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"

PACKAGE = "x0x"

# Daemon-mesh integration-test binaries that a CI selector runs with more
# than one test per nextest invocation. Single-test selectors gain nothing
# from the group, so they are deliberately absent.
SERIALIZED_MESH_BINARIES = ("delegation_spaces",)

# The issue #321 acceptance cases (`.github/workflows/integration.yml`, the
# "delegation and cold-wake acceptance" step). They must exist in the binary
# and in the workflow selector, so a rename cannot leave this guard checking
# names that no longer run.
ACCEPTANCE_CASES = (
    "delegation_survives_restart_via_history",
    "delegation_carrier_verified_history_survives_receiver_restart",
    "delegated_child_cold_wake_rehydrates_carrier_and_sends_as",
)

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


@dataclass(frozen=True)
class CaseId:
    """The identity nextest filters see for one test."""

    package: str
    binary: str
    kind: str
    name: str

    @property
    def binary_id(self) -> str:
        return f"{self.package}::{self.binary}"


def _toml_string(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    raise ConfigError(f"expected a quoted TOML string, got {raw!r}")


def parse_overrides(text: str) -> list[Override]:
    """Parse `[[profile.default.overrides]]` blocks from ACTIVE lines only.

    A commented-out key or header is not configuration — nextest never sees
    it, so the guard must not either. Every block must carry an active
    `filter` (nextest rejects an override without one); a `platform` key
    makes the match host-dependent, which this guard does not model. Both
    fail closed via ConfigError.
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
                if key == "platform":
                    raise ConfigError(
                        f"override at line {i + 1} sets `platform`; the guard "
                        "cannot evaluate host-dependent overrides"
                    )
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


# --- filterset evaluation -------------------------------------------------

# Default matcher per predicate (nextest filterset reference, "Default
# matchers"): contains for test(), glob for the binary and package
# predicates, equality for kind().
_DEFAULT_MATCHER = {
    "test": "~",
    "binary": "#",
    "binary_id": "#",
    "package": "#",
    "kind": "=",
}

_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "/": "/", ")": ")", ",": ","}


def _unescape(raw: str, expression: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        char = raw[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        if i + 1 >= len(raw):
            raise ConfigError(f"dangling escape in filter {expression!r}")
        nxt = raw[i + 1]
        if nxt in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[nxt])
            i += 2
            continue
        match = re.match(r"u\{([0-9a-fA-F]{1,6})\}", raw[i + 1 :])
        if match is None:
            raise ConfigError(f"invalid escape \\{nxt} in filter {expression!r}")
        out.append(chr(int(match.group(1), 16)))
        i += 1 + match.end()
    return "".join(out)


def _matches(kind: str, pattern: str, value: str, expression: str) -> bool:
    if kind == "=":
        return value == pattern
    if kind == "~":
        return pattern in value
    if kind == "/":
        try:
            return re.search(pattern, value) is not None
        except re.error as err:
            raise ConfigError(f"bad regex {pattern!r} in filter {expression!r}") from err
    if kind == "#":
        if "{" in pattern or "**" in pattern:
            # globset alternation and recursive wildcards have no faithful
            # fnmatch equivalent: fail closed rather than guess.
            raise ConfigError(f"unsupported glob {pattern!r} in filter {expression!r}")
        return fnmatch.fnmatchcase(value, pattern)
    raise ConfigError(f"unknown matcher {kind!r} in filter {expression!r}")


_OPERATOR_WORDS = {"not": "not", "and": "and", "or": "or"}
_OPERATOR_CHARS = {"!": "not", "&": "and", "-": "and_not", "|": "or", "+": "or"}


def _tokenize(expression: str) -> list[tuple[str, str]]:
    """Split a filterset into tokens.

    Token kinds: `pred` (value `name\\0matcher\\0pattern`), `not`, `and`,
    `and_not` (the `-` difference operator), `or`, `(`, `)`.
    """
    tokens: list[tuple[str, str]] = []
    pos = 0
    n = len(expression)
    while pos < n:
        char = expression[pos]
        if char.isspace():
            pos += 1
            continue
        if char in "()":
            tokens.append((char, char))
            pos += 1
            continue
        if char in _OPERATOR_CHARS:
            tokens.append((_OPERATOR_CHARS[char], char))
            pos += 1
            continue
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expression[pos:])
        if match is None:
            raise ConfigError(
                f"unexpected {char!r} at offset {pos} in filter {expression!r}"
            )
        word = match.group(0)
        pos += len(word)
        if word in _OPERATOR_WORDS:
            tokens.append((_OPERATOR_WORDS[word], word))
            continue
        # A predicate: name(...) with its argument read raw. A regex
        # argument may itself contain `)` (e.g. `/(^|::)w3h_/`), so it is
        # scanned to its closing unescaped `/`.
        while pos < n and expression[pos].isspace():
            pos += 1
        if pos >= n or expression[pos] != "(":
            raise ConfigError(
                f"expected '(' after {word!r} at offset {pos} in filter {expression!r}"
            )
        pos += 1
        while pos < n and expression[pos].isspace():
            pos += 1
        if pos < n and expression[pos] == "/":
            end = pos + 1
            while end < n and expression[end] != "/":
                end += 2 if expression[end] == "\\" else 1
            if end >= n:
                raise ConfigError(f"unterminated regex in filter {expression!r}")
            matcher, pattern = "/", expression[pos + 1 : end].replace("\\/", "/")
            pos = end + 1
            while pos < n and expression[pos].isspace():
                pos += 1
            if pos >= n or expression[pos] != ")":
                raise ConfigError(f"expected ')' after regex in filter {expression!r}")
            pos += 1
        else:
            end = pos
            while end < n and expression[end] != ")":
                end += 2 if expression[end] == "\\" else 1
            if end >= n:
                raise ConfigError(f"unterminated argument in filter {expression!r}")
            raw = expression[pos:end].strip()
            pos = end + 1
            matcher = ""
            if raw[:1] in ("=", "~", "#"):
                matcher, raw = raw[0], raw[1:]
            pattern = _unescape(raw, expression)
        tokens.append(("pred", f"{word}\0{matcher}\0{pattern}"))
    return tokens


def evaluate_filter(expression: str, test: CaseId) -> bool:
    """Evaluate a nextest filterset against one test.

    Grammar, tightest first (nextest filterset reference): `()`, then
    `not`/`!`, then `and`/`&`/`-`, then `or`/`|`/`+`; each level binds left
    to right. Predicates: `all()`, `none()`, `test()`, `binary()`,
    `binary_id()`, `package()`, `kind()`, with the `=`, `~`, `/regex/` and
    `#glob` matchers and nextest's per-predicate default matcher. Anything
    else (`deps()`, `rdeps()`, `platform()`, `default()`, ...) raises
    ConfigError so the guard fails closed and gets taught the new syntax.
    """
    tokens = _tokenize(expression)
    pos = 0

    def peek() -> str | None:
        return tokens[pos][0] if pos < len(tokens) else None

    def advance() -> tuple[str, str]:
        nonlocal pos
        if pos >= len(tokens):
            raise ConfigError(f"unexpected end of filter {expression!r}")
        token = tokens[pos]
        pos += 1
        return token

    def predicate(value: str) -> bool:
        name, matcher, pattern = value.split("\0")
        if name == "all":
            if matcher or pattern:
                raise ConfigError(f"all() takes no argument in filter {expression!r}")
            return True
        if name == "none":
            if matcher or pattern:
                raise ConfigError(f"none() takes no argument in filter {expression!r}")
            return False
        if name not in _DEFAULT_MATCHER:
            raise ConfigError(f"unsupported predicate {name!r} in filter {expression!r}")
        if not pattern and matcher != "=":
            raise ConfigError(f"empty argument to {name}() in filter {expression!r}")
        subject = {
            "test": test.name,
            "binary": test.binary,
            "binary_id": test.binary_id,
            "package": test.package,
            "kind": test.kind,
        }[name]
        return _matches(matcher or _DEFAULT_MATCHER[name], pattern, subject, expression)

    def unary() -> bool:
        kind, value = advance()
        if kind == "not":
            return not unary()
        if kind == "(":
            result = or_expr()
            closing, _ = advance()
            if closing != ")":
                raise ConfigError(f"expected ')' in filter {expression!r}")
            return result
        if kind == "pred":
            return predicate(value)
        raise ConfigError(f"unexpected {value!r} in filter {expression!r}")

    def and_expr() -> bool:
        value = unary()
        while peek() in ("and", "and_not"):
            op, _ = advance()
            rhs = unary()
            value = value and rhs if op == "and" else value and not rhs
        return value

    def or_expr() -> bool:
        value = and_expr()
        while peek() == "or":
            advance()
            rhs = and_expr()
            value = value or rhs
        return value

    if not tokens:
        raise ConfigError("empty filter expression")
    result = or_expr()
    if pos != len(tokens):
        raise ConfigError(f"trailing input {tokens[pos][1]!r} in filter {expression!r}")
    return result


# --- effective assignment -------------------------------------------------


def binary_tests(binary: str) -> list[str]:
    """Test function names in `tests/<binary>.rs` (top-level, as nextest names them)."""
    source = (ROOT / "tests" / f"{binary}.rs").read_text(encoding="utf-8")
    names = re.findall(
        r"#\[(?:tokio::)?test(?:\([^)]*\))?\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)",
        source,
    )
    if not names:
        raise ConfigError(f"no test functions found in tests/{binary}.rs")
    return names


def effective_test_group(text: str, test: CaseId) -> str | None:
    """The test-group nextest would apply to `test`, or None.

    Per-setting precedence: the first override that matches the test AND
    configures `test-group` wins. A matching override that does not set
    `test-group` is ignored for this setting.
    """
    for override in parse_overrides(text):
        if override.test_group is not None and evaluate_filter(override.filter, test):
            return override.test_group
    return None


def assert_serialized_in_quic_localhost(
    text: str, binary: str, tests: list[str] | None = None
) -> None:
    for name in tests if tests is not None else binary_tests(binary):
        test = CaseId(PACKAGE, binary, "test", name)
        group = effective_test_group(text, test)
        if group != "quic-localhost":
            raise AssertionError(
                f".config/nextest.toml must run {binary}::{name} in the "
                f"quic-localhost test-group (#1283); the effective group is "
                f"{group!r}. The daemon-mesh selector would otherwise run its "
                "pairs concurrently in one loopback namespace."
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


def _ds(name: str = "delegation_survives_restart_via_history") -> CaseId:
    return CaseId(PACKAGE, "delegation_spaces", "test", name)


def _group_override(text: str, test: CaseId) -> Override:
    for override in parse_overrides(text):
        if override.test_group is not None and evaluate_filter(override.filter, test):
            return override
    raise AssertionError(f"no test-group override matches {test} in the config")


def _insert_before_first_override(text: str, block: list[str]) -> str:
    lines = text.splitlines()
    first = next(i for i, line in enumerate(lines) if line.strip() == OVERRIDES_HEADER)
    return "\n".join(lines[:first] + block + [""] + lines[first:])


class FilterEvaluation(unittest.TestCase):
    def test_binary_predicate_matches_only_the_named_binary(self) -> None:
        self.assertTrue(evaluate_filter("binary(delegation_spaces)", _ds()))
        self.assertFalse(evaluate_filter("binary(other)", _ds()))

    def test_negated_binary_does_not_match(self) -> None:
        self.assertFalse(evaluate_filter("not binary(delegation_spaces)", _ds()))
        self.assertFalse(evaluate_filter("!binary(delegation_spaces)", _ds()))

    def test_or_with_a_word_operator_parses(self) -> None:
        # Codex review: the old lookahead consumed `or` and failed.
        self.assertTrue(evaluate_filter("binary(other) or binary(delegation_spaces)", _ds()))
        self.assertTrue(evaluate_filter("binary(other) + binary(delegation_spaces)", _ds()))

    def test_and_binds_tighter_than_or(self) -> None:
        # Codex review: the right operand of `|` must be a full and-chain.
        self.assertTrue(
            evaluate_filter("binary(delegation_spaces) | binary(other) & binary(no)", _ds())
        )
        self.assertFalse(
            evaluate_filter("binary(other) | binary(delegation_spaces) & binary(no)", _ds())
        )
        self.assertTrue(
            evaluate_filter("binary(no) & binary(other) | binary(delegation_spaces)", _ds())
        )
        self.assertFalse(
            evaluate_filter("(binary(other) | binary(delegation_spaces)) & binary(no)", _ds())
        )

    def test_not_binds_tighter_than_and_and_or(self) -> None:
        self.assertTrue(evaluate_filter("not binary(other) | binary(no)", _ds()))
        self.assertTrue(
            evaluate_filter("not binary(other) & binary(delegation_spaces)", _ds())
        )
        self.assertFalse(evaluate_filter("not (binary(other) | binary(delegation_spaces))", _ds()))

    def test_difference_operator(self) -> None:
        self.assertTrue(evaluate_filter("binary(delegation_spaces) - test(=nope)", _ds()))
        self.assertFalse(evaluate_filter("binary(delegation_spaces) - test(delegation_)", _ds()))
        # Left-to-right within the and-level.
        self.assertFalse(
            evaluate_filter("binary(delegation_spaces) - test(delegation_) & all()", _ds())
        )

    def test_test_predicate_matchers(self) -> None:
        test = _ds()
        self.assertTrue(evaluate_filter("test(survives_restart)", test))  # contains
        self.assertTrue(evaluate_filter("test(~survives_restart)", test))
        self.assertFalse(evaluate_filter("test(=survives_restart)", test))
        self.assertTrue(evaluate_filter(f"test(={test.name})", test))
        self.assertTrue(evaluate_filter("test(/^delegation_/)", test))
        self.assertTrue(evaluate_filter("test(/(^|::)delegation_/)", test))  # ')' in regex
        self.assertFalse(evaluate_filter("test(/^d4_/)", test))
        self.assertTrue(evaluate_filter("test(#delegation_*)", test))
        self.assertFalse(evaluate_filter("test(#survives*)", test))

    def test_binary_default_matcher_is_glob(self) -> None:
        self.assertTrue(evaluate_filter("binary(delegation_*)", _ds()))
        self.assertFalse(evaluate_filter("binary(delegation)", _ds()))
        self.assertTrue(evaluate_filter("binary_id(x0x::delegation_spaces)", _ds()))
        self.assertTrue(evaluate_filter("package(x0x) & kind(test)", _ds()))

    def test_every_live_override_filter_parses(self) -> None:
        for override in parse_overrides(_config_text()):
            with self.subTest(filter=override.filter):
                evaluate_filter(override.filter, _ds())

    def test_unsupported_or_malformed_filters_fail_closed(self) -> None:
        for bad in (
            "deps(x)",
            "platform(host)",
            "binary(delegation_spaces",
            "binary)",
            "binary(a) |",
            "binary(a) binary(b)",
            "(binary(a)",
            "test(/unterminated)",
            "binary({a,b})",
            "",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    evaluate_filter(bad, _ds())


class EffectiveAssignment(unittest.TestCase):
    def test_acceptance_cases_exist_in_binary_and_workflow(self) -> None:
        names = binary_tests("delegation_spaces")
        workflow = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")
        for case in ACCEPTANCE_CASES:
            with self.subTest(case=case):
                self.assertIn(case, names)
                self.assertIn(f"test(={case})", workflow)

    def test_every_mesh_test_is_effectively_in_the_quic_localhost_group(self) -> None:
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
            effective_test_group(text, _ds())


class NegativeControls(unittest.TestCase):
    """In-memory mutations that must be rejected (#1283 reviews)."""

    def test_commented_out_group_assignment_is_rejected(self) -> None:
        text = _config_text()
        override = _group_override(text, _ds())
        assert override.group_line is not None
        lines = text.splitlines()
        lines[override.group_line] = "# " + lines[override.group_line]
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_negated_filter_is_rejected(self) -> None:
        text = _config_text()
        override = _group_override(text, _ds())
        lines = text.splitlines()
        lines[override.filter_line] = f'filter = "not ({override.filter})"'
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_test_predicate_that_drops_the_acceptance_cases_is_rejected(self) -> None:
        # Codex review: `binary(delegation_spaces) & not test(delegation_)`
        # keeps the binary in the filter but removes two acceptance cases.
        text = _config_text()
        override = _group_override(text, _ds())
        lines = text.splitlines()
        lines[override.filter_line] = (
            'filter = "binary(delegation_spaces) & not test(delegation_)"'
        )
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_difference_that_drops_one_acceptance_case_is_rejected(self) -> None:
        text = _config_text()
        override = _group_override(text, _ds())
        lines = text.splitlines()
        lines[override.filter_line] = (
            'filter = "binary(delegation_spaces) - '
            'test(=delegated_child_cold_wake_rehydrates_carrier_and_sends_as)"'
        )
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_retargeted_group_is_rejected(self) -> None:
        text = _config_text()
        override = _group_override(text, _ds())
        assert override.group_line is not None
        lines = text.splitlines()
        lines[override.group_line] = 'test-group = "membership-cluster"'
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost("\n".join(lines), "delegation_spaces")

    def test_earlier_test_name_override_reassigning_acceptance_cases_is_rejected(
        self,
    ) -> None:
        # Codex review: an earlier test-name override with its own
        # test-group wins for those tests, though the binary block is intact.
        text = _insert_before_first_override(
            _config_text(),
            [
                OVERRIDES_HEADER,
                "filter = \"test(=delegation_survives_restart_via_history) | "
                "test(=delegation_carrier_verified_history_survives_receiver_restart)\"",
                'test-group = "membership-cluster"',
            ],
        )
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost(text, "delegation_spaces")

    def test_earlier_contains_match_reassigning_one_case_is_rejected(self) -> None:
        text = _insert_before_first_override(
            _config_text(),
            [
                OVERRIDES_HEADER,
                'filter = "test(cold_wake)"',
                'test-group = "membership-cluster"',
            ],
        )
        with self.assertRaises(AssertionError):
            assert_serialized_in_quic_localhost(text, "delegation_spaces")

    def test_commented_out_override_header_is_not_config(self) -> None:
        text = _config_text()
        override = _group_override(text, _ds())
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


class PositiveControls(unittest.TestCase):
    """Valid configurations the guard must keep accepting (#1283 review)."""

    def test_earlier_timeout_only_override_does_not_erase_the_group(self) -> None:
        # Codex review: nextest resolves precedence per setting. An earlier
        # override that only sets a timeout is ignored for test-group, so the
        # later #1283 assignment still applies.
        text = _insert_before_first_override(
            _config_text(),
            [
                OVERRIDES_HEADER,
                'filter = "binary(delegation_spaces)"',
                'slow-timeout = { period = "120s", terminate-after = 8 }',
            ],
        )
        assert_serialized_in_quic_localhost(text, "delegation_spaces")

    def test_earlier_override_assigning_the_same_group_passes(self) -> None:
        text = _insert_before_first_override(
            _config_text(),
            [
                OVERRIDES_HEADER,
                'filter = "test(=delegation_survives_restart_via_history)"',
                'test-group = "quic-localhost"',
                "threads-required = 2",
            ],
        )
        assert_serialized_in_quic_localhost(text, "delegation_spaces")

    def test_unrelated_earlier_reassignment_passes(self) -> None:
        text = _insert_before_first_override(
            _config_text(),
            [
                OVERRIDES_HEADER,
                'filter = "binary(other) | test(=unrelated_case) & binary(delegation_spaces)"',
                'test-group = "membership-cluster"',
            ],
        )
        assert_serialized_in_quic_localhost(text, "delegation_spaces")


if __name__ == "__main__":
    unittest.main()
