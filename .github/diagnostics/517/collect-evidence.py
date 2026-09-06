#!/usr/bin/env python3
"""Fail-closed whitelist collector for the #517 disposable diagnostic."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

SAFE_TOP = {"status", "result_shape_valid", "module_sha256", "result"}
SAFE_RESULT = {
    "name", "status", "error", "unsupported", "scope",
    "historical_recovery_secs", "live_recovery_secs", "interop_key_secs",
    "joiner_anchored", "legacy_owner_alive", "legacy_joiner_alive",
    "legacy_joiner_put_status", "legacy_local_fork",
    "legacy_write_propagated_to_owner", "owner_kept_owned_exact",
    "owner_clean_of_legacy_write",
}
SECRET_MARKERS = ("api-token", "authorization", "bearer ", "private key",
                  "secret", "password", "raw_value", "raw value")


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular file: {path}")
    return path


def safe_value(key, value):
    if key not in SAFE_RESULT:
        return None
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def sanitize(report):
    if not isinstance(report, dict):
        raise ValueError("driver report is not an object")
    result = report.get("result")
    if not isinstance(result, list) or len(result) != 2:
        raise ValueError("driver result is not exactly two items")
    sanitized = {key: report[key] for key in SAFE_TOP if key in report and key != "result"}
    rows = []
    for row in result:
        if not isinstance(row, dict):
            raise ValueError("driver result item is not an object")
        rows.append({key: value for key, value in
                     ((key, safe_value(key, row[key])) for key in SAFE_RESULT
                      if key in row)
                     if value is not None})
    sanitized["result"] = rows
    encoded = json.dumps(sanitized, sort_keys=True)
    lowered = encoded.lower()
    if any(marker in lowered for marker in SECRET_MARKERS):
        raise ValueError("sanitized report contains a secret marker")
    return sanitized


def wrapper_evidence(wrapper_stdout):
    lines = regular(wrapper_stdout).read_text(errors="strict").splitlines()
    prefix = "Isolation evidence: "
    candidates = [Path(line[len(prefix):]) for line in lines if line.startswith(prefix)]
    if len(candidates) != 1:
        raise ValueError("expected one isolation evidence path")
    evidence = candidates[0]
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if evidence.is_symlink() or not evidence.is_dir():
        raise ValueError("isolation evidence root is not a real directory")
    if not evidence.resolve().is_relative_to(runner_temp):
        raise ValueError("isolation evidence escaped RUNNER_TEMP")
    return evidence


def copy_regular(src, dest):
    regular(src)
    if dest.exists() or dest.is_symlink():
        raise ValueError(f"collector destination already exists: {dest}")
    shutil.copyfile(src, dest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper-stdout", required=True, type=Path)
    parser.add_argument("--driver-result", required=True, type=Path)
    parser.add_argument("--driver-exit", required=True, type=Path)
    parser.add_argument("--source-meta", required=True, type=Path)
    parser.add_argument("--current-meta", required=True, type=Path)
    parser.add_argument("--legacy-meta", required=True, type=Path)
    parser.add_argument("--version-meta", required=True, type=Path)
    parser.add_argument("--version-exit", required=True, type=Path)
    parser.add_argument("--version-wrapper-stdout", required=True, type=Path)
    parser.add_argument("--upload-dir", required=True, type=Path)
    args = parser.parse_args()

    upload = args.upload_dir
    if upload.exists():
        if upload.is_symlink() or not upload.is_dir() or any(upload.iterdir()):
            raise ValueError("upload directory must be a fresh real directory")
    else:
        upload.mkdir(parents=True)

    errors = []
    # Copy known structured metadata even when setup/driver failed before
    # producing a result or namespace path. Missing receipts are explicit.
    known_sources = (
        (args.source_meta, "source.json"), (args.current_meta, "current.json"),
        (args.legacy_meta, "legacy.json"), (args.version_meta, "version.json"),
        (args.driver_exit, "driver-exit.json"), (args.version_exit, "version-exit.json"),
    )
    for source, name in known_sources:
        try:
            copy_regular(source, upload / name)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")

    evidences = []
    for wrapper, prefix in ((args.wrapper_stdout, "driver"),
                            (args.version_wrapper_stdout, "version")):
        try:
            evidences.append((prefix, wrapper_evidence(wrapper)))
        except (OSError, ValueError) as exc:
            errors.append(f"{prefix}-evidence: {exc}")
    for prefix, evidence in evidences:
        for source_name, output_name in (
                ("admission.json", f"{prefix}-admission.json"),
                ("exit.json", f"{prefix}-exit-runtime.json"),
                ("supervisor.json", f"{prefix}-supervisor.json")):
            try:
                copy_regular(evidence / source_name, upload / output_name)
            except (OSError, ValueError) as exc:
                errors.append(f"{output_name}: {exc}")

    report_error = None
    try:
        report = json.loads(regular(args.driver_result).read_text())
        sanitized = sanitize(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report_error = f"driver report unavailable: {type(exc).__name__}: {exc}"
        sanitized = {"status": "driver-report-unavailable",
                     "result_shape_valid": False}
        errors.append(report_error)
    (upload / "mixed-version-result.json").write_text(
        json.dumps(sanitized, indent=2) + "\n")
    (upload / "collection-status.json").write_text(json.dumps({
        "status": "collected-with-errors" if errors else "collected",
        "errors": errors,
        "driver_report_available": report_error is None,
    }, indent=2) + "\n")
    for path in upload.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe collector output: {path}")
        lowered = path.read_text(errors="strict").lower()
        if any(marker in lowered for marker in SECRET_MARKERS):
            raise ValueError(f"secret marker in collector output: {path.name}")
    print(json.dumps({"status": "collected" if not errors else "collected-with-errors",
                      "files": sorted(p.name for p in upload.iterdir()),
                      "errors": errors}))
    return 2 if errors else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "collector-error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
