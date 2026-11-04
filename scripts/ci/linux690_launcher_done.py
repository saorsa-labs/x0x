#!/usr/bin/env python3
"""Check the done.json that one #690 launcher lifecycle case writes."""
import json
from pathlib import Path
import sys

# Expected rollback verdict per case: (class, reason substrings), or None.
VERDICTS = {
    "exec": ("failed", ("launch attempts exhausted", "exec failed")),
    "crash": ("failed", ("launch attempts exhausted", "candidate exited before commit")),
    "hang": ("failed", ("launch attempts exhausted", "readiness deadline reached")),
    "restart": ("interrupted", ("launcher died during exec",)),
    "restart-child": ("interrupted", ("launcher lost child custody",)),
    "stop": None,
}


def fail(message: str, value: object) -> None:
    raise AssertionError(f"{message}: {value!r}")


def check(root: Path, case: str) -> None:
    if case not in VERDICTS:
        raise ValueError(f"unknown launcher case {case!r}")
    done = json.loads((root / "done.json").read_text(encoding="utf-8"))
    if done.get("case") != case:
        fail(f"case is not {case}", done)
    attempts = 1 if case in ("restart", "restart-child", "stop") else 3
    if done.get("attempts") != attempts:
        fail(f"attempts is not {attempts}", done)
    if case.startswith("restart"):
        deadline = int((root / "original-deadline").read_text(encoding="utf-8"))
        if done.get("deadline_ms") != deadline:
            fail(f"deadline_ms is not {deadline}", done)
        first = json.loads((root / "first-invocation.json").read_text(encoding="utf-8"))
        if first.get("pid") == done.get("pid") or first.get("invocation") == done.get("invocation"):
            fail("restored launcher reused the first pid or invocation", (first, done))
    restored = root / "restored-started.json"
    if case == "stop" and restored.exists():
        fail("stop case restored a child", done)
    if case != "stop" and not restored.is_file():
        fail("restored-started.json is missing", done)
    expected = VERDICTS[case]
    verdict = done.get("verdict")
    if expected is None:
        if verdict is not None:
            fail("stop case has a verdict", done)
        return
    if not isinstance(verdict, dict):
        fail("verdict is missing", done)
    klass, needles = expected
    if verdict.get("class") != klass:
        fail(f"verdict class is not {klass}", done)
    reason = verdict.get("reason")
    if not isinstance(reason, str) or not all(n in reason for n in needles):
        fail(f"verdict reason does not contain {needles}", done)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <case_dir> <case_name>", file=sys.stderr)
        return 2
    try:
        check(Path(argv[1]), argv[2])
    except (AssertionError, ValueError, OSError, KeyError) as error:
        print(f"launcher case {argv[2]}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
