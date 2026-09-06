#!/usr/bin/env python3
"""Run only the existing #517 mixed-version prerequisite functions.

This helper is an external review artifact. It must be run from an already
admitted isolated Linux namespace/VM; it does not alter the x0x checkout.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


EXPECTED_RESULT_NAMES = frozenset({
    "mixed_version_skew_load_bearing",
    "mixed_version_skew_degraded",
})


def exact_result_shape(result):
    """Require the two named gates before applying any status predicate."""
    return (isinstance(result, list) and len(result) == 2
            and all(isinstance(item, dict) for item in result)
            and {item.get("name") for item in result} == EXPECTED_RESULT_NAMES)


def persist_report(path, report):
    if path is None:
        return
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"report file must be fresh: {path}")
    path.write_text(json.dumps(report, indent=2, default=str) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--current-binary", required=True, type=Path)
    parser.add_argument("--legacy-binary", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--report-file", type=Path)
    parser.add_argument("--api-base", type=int, default=27850)
    parser.add_argument("--quic-base", type=int, default=27950)
    parser.add_argument("--stagger-secs", type=float, default=15.0)
    parser.add_argument("--poll-interval", type=float, default=1.5)
    parser.add_argument("--cold-gate", type=float, default=120.0)
    parser.add_argument("--live-gate", type=float, default=60.0)
    parser.add_argument("--fork-window", type=float, default=20.0)
    args = parser.parse_args()

    module_path = args.repo_root / "tests/convergence/convergence_soak.py"
    required = {
        "module": module_path,
        "current_binary": args.current_binary,
        "legacy_binary": args.legacy_binary,
    }
    missing = [f"{label}: {path}" for label, path in required.items()
               if not path.is_file()]
    if missing:
        report = {"status": "driver-error", "result_shape_valid": False,
                  "missing": missing}
        persist_report(args.report_file, report)
        print(json.dumps(report), file=sys.stderr)
        return 2

    spec = importlib.util.spec_from_file_location(
        "x0x_convergence_soak_release517", module_path)
    if spec is None or spec.loader is None:
        report = {"status": "driver-error", "result_shape_valid": False,
                  "error": "could not load convergence module"}
        persist_report(args.report_file, report)
        print(json.dumps(report), file=sys.stderr)
        return 2
    module = importlib.util.module_from_spec(spec)
    # Required for dataclasses and any module self-reference during loading.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        report = {"status": "driver-error", "result_shape_valid": False,
                  "error": f"module import failed: {exc}"}
        persist_report(args.report_file, report)
        print(json.dumps(report), file=sys.stderr)
        return 2

    if args.out_dir.exists() and any(args.out_dir.iterdir()):
        report = {"status": "driver-error", "result_shape_valid": False,
                  "error": "out-dir must be a fresh empty root",
                  "out_dir": str(args.out_dir)}
        persist_report(args.report_file, report)
        print(json.dumps(report), file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    driver_args = argparse.Namespace(
        legacy_binary=args.legacy_binary,
        x0xd=args.current_binary,
        log_level="info",
        api_base=args.api_base,
        quic_base=args.quic_base,
        stagger_secs=args.stagger_secs,
        cold_gate=args.cold_gate,
        poll_interval=args.poll_interval,
        live_gate=args.live_gate,
        fork_window=args.fork_window,
    )
    result = module.run_mixed_version_gate(driver_args, args.out_dir)
    exact_results = exact_result_shape(result)
    report = {
        "status": ("pass" if exact_results
                   and all(item.get("status") == "pass" for item in result)
                   else "fail"),
        "result_shape_valid": exact_results,
        "module": str(module_path),
        "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "result": result,
    }
    persist_report(args.report_file, report)
    print(json.dumps(report, indent=2, default=str))
    if not exact_results:
        return 2
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
