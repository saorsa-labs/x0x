#!/usr/bin/env python3
"""Check cargo-llvm-cov LCOV output against coverage-thresholds.toml."""

from __future__ import annotations

import argparse
import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
import sys


@dataclass(frozen=True)
class CoverageRecord:
    path: str
    found: int
    hit: int

    @property
    def percent(self) -> float:
        if self.found == 0:
            return 100.0
        return (self.hit / self.found) * 100.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate global and module coverage thresholds from LCOV."
    )
    parser.add_argument("--lcov", default="lcov.info", help="Path to lcov.info")
    parser.add_argument(
        "--thresholds",
        default="coverage-thresholds.toml",
        help="Path to coverage threshold config",
    )
    parser.add_argument(
        "--enforce-global",
        action="store_true",
        help="Fail if global line coverage is below [global].line_floor",
    )
    parser.add_argument(
        "--enforce-modules",
        action="store_true",
        help="Fail advisory module thresholds instead of warning",
    )
    return parser.parse_args()


def normalize_source(source: str, repo_root: Path) -> str:
    source_path = Path(source)
    if not source_path.is_absolute():
        source_path = repo_root / source_path

    try:
        return source_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return source.replace("\\", "/")


def parse_lcov(path: Path, repo_root: Path) -> list[CoverageRecord]:
    records: list[CoverageRecord] = []
    source: str | None = None
    line_hits: dict[int, int] = {}
    fallback_found: int | None = None
    fallback_hit: int | None = None

    def finish_record() -> None:
        nonlocal source, line_hits, fallback_found, fallback_hit
        if source is None:
            return
        if line_hits:
            found = len(line_hits)
            hit = sum(1 for count in line_hits.values() if count > 0)
        else:
            found = fallback_found or 0
            hit = fallback_hit or 0
        records.append(
            CoverageRecord(
                path=normalize_source(source, repo_root),
                found=found,
                hit=hit,
            )
        )
        source = None
        line_hits = {}
        fallback_found = None
        fallback_hit = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith("SF:"):
            finish_record()
            source = raw_line[3:]
        elif raw_line.startswith("DA:"):
            fields = raw_line[3:].split(",")
            if len(fields) >= 2:
                try:
                    line_hits[int(fields[0])] = int(fields[1])
                except ValueError:
                    raise SystemExit(f"invalid DA line in {path}: {raw_line}")
        elif raw_line.startswith("LF:"):
            fallback_found = int(raw_line[3:])
        elif raw_line.startswith("LH:"):
            fallback_hit = int(raw_line[3:])
        elif raw_line == "end_of_record":
            finish_record()

    finish_record()
    return records


def parse_scalar(path: Path, line_number: int, raw_value: str) -> str | int | float | bool:
    value = raw_value.strip().removesuffix(",").strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return float(value) if "." in value else int(value)
    except ValueError:
        raise SystemExit(f"{path}:{line_number}: unsupported value {raw_value!r}")


def parse_threshold_config(path: Path) -> dict:
    """Parse the small TOML subset used by coverage-thresholds.toml."""
    data: dict[str, object] = {}
    current_table: dict[str, object] | None = None
    array_key: str | None = None
    array_values: list[object] = []

    def finish_array(line_number: int) -> None:
        nonlocal array_key, array_values
        if current_table is None or array_key is None:
            raise SystemExit(f"{path}:{line_number}: array outside a table")
        current_table[array_key] = array_values
        array_key = None
        array_values = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if array_key is not None:
            if line == "]":
                finish_array(line_number)
                continue
            array_values.append(parse_scalar(path, line_number, line))
            continue

        if line == "[global]":
            global_table: dict[str, object] = {}
            data["global"] = global_table
            current_table = global_table
            continue

        if line == "[[modules]]":
            modules = data.setdefault("modules", [])
            if not isinstance(modules, list):
                raise SystemExit(f"{path}:{line_number}: modules must be an array")
            module_table: dict[str, object] = {}
            modules.append(module_table)
            current_table = module_table
            continue

        if current_table is None or "=" not in line:
            raise SystemExit(f"{path}:{line_number}: expected table key/value")

        key, raw_value = line.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value == "[":
            array_key = key
            array_values = []
            continue

        current_table[key] = parse_scalar(path, line_number, raw_value)

    if array_key is not None:
        raise SystemExit(f"{path}: unterminated array for {array_key}")

    return data


def load_config(path: Path) -> dict:
    data = parse_threshold_config(path)
    global_cfg = data.get("global")
    if not isinstance(global_cfg, dict):
        raise SystemExit(f"{path} must contain a [global] table")
    if "line_floor" not in global_cfg:
        raise SystemExit(f"{path} [global] must set line_floor")

    modules = data.get("modules", [])
    if not isinstance(modules, list):
        raise SystemExit(f"{path} modules must be an array of tables")

    for index, module in enumerate(modules, start=1):
        for key in ("name", "paths", "target", "mode"):
            if key not in module:
                raise SystemExit(f"{path} module #{index} missing {key}")
        if module["mode"] not in {"advisory", "required"}:
            raise SystemExit(
                f"{path} module {module['name']} has invalid mode {module['mode']}"
            )
        if not module["paths"]:
            raise SystemExit(f"{path} module {module['name']} has no paths")

    return data


def coverage_percent(records: list[CoverageRecord]) -> tuple[float, int, int]:
    found = sum(record.found for record in records)
    hit = sum(record.hit for record in records)
    if found == 0:
        return 100.0, hit, found
    return (hit / found) * 100.0, hit, found


def matching_records(
    records: list[CoverageRecord], patterns: list[str]
) -> list[CoverageRecord]:
    return [
        record
        for record in records
        if any(fnmatch.fnmatch(record.path, pattern) for pattern in patterns)
    ]


def warn(message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::warning title=Coverage threshold::{message}")
    else:
        print(f"warning: {message}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    repo_root = Path.cwd()
    lcov_path = Path(args.lcov)
    config_path = Path(args.thresholds)

    if not lcov_path.exists():
        raise SystemExit(f"LCOV file not found: {lcov_path}")
    if not config_path.exists():
        raise SystemExit(f"threshold config not found: {config_path}")

    config = load_config(config_path)
    records = parse_lcov(lcov_path, repo_root)
    if not records:
        raise SystemExit(f"no coverage records found in {lcov_path}")

    overall_percent, overall_hit, overall_found = coverage_percent(records)
    global_floor = float(config["global"]["line_floor"])
    print(
        f"overall line coverage: {overall_percent:.2f}% "
        f"({overall_hit}/{overall_found}), floor {global_floor:.2f}%"
    )

    failures: list[str] = []
    if args.enforce_global and overall_percent + 1e-9 < global_floor:
        failures.append(
            f"overall coverage {overall_percent:.2f}% is below {global_floor:.2f}%"
        )

    for module in config.get("modules", []):
        paths = list(module["paths"])
        matches = matching_records(records, paths)
        if not matches:
            message = f"{module['name']}: no LCOV records matched {paths}"
            if args.enforce_modules or module["mode"] == "required":
                failures.append(message)
            else:
                warn(message)
            continue

        module_percent, module_hit, module_found = coverage_percent(matches)
        target = float(module["target"])
        print(
            f"{module['name']}: {module_percent:.2f}% "
            f"({module_hit}/{module_found}), target {target:.2f}% "
            f"({module['mode']})"
        )
        if module_percent + 1e-9 < target:
            message = (
                f"{module['name']} coverage {module_percent:.2f}% is below "
                f"{target:.2f}%"
            )
            if args.enforce_modules or module["mode"] == "required":
                failures.append(message)
            else:
                warn(message)

    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
