#!/usr/bin/env python3
"""Stage build artifacts with reproducible source and dependency custody."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NoReturn


STATE = ".provenance-state.json"
MANIFEST = "build-provenance.json"
ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")
RUSTUP_CROSS_PREAMBLE = re.compile(
    r"  (?P<version>[0-9]+\.[0-9]+\.[0-9]+)-x86_64-unknown-linux-gnu unchanged - "
    r"rustc (?P=version) \([0-9a-f]{9,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)"
)


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def require_clean_tracked_source(repo: Path) -> None:
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        fail("tracked source differs from checkout")


def tracked_source_sha256(repo: Path) -> str:
    listing = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-s", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if listing.returncode != 0:
        fail("git ls-files failed")
    digest = hashlib.sha256()
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        path = repo / os.fsdecode(raw_path)
        digest.update(metadata)
        digest.update(b"\0")
        digest.update(raw_path)
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(os.fsencode(os.readlink(path)))
        elif path.is_file():
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
        else:
            fail(f"tracked path is unavailable: {os.fsdecode(raw_path)}")
        digest.update(b"\0")
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid provenance file {path.name}: {type(error).__name__}")
    if not isinstance(value, dict):
        fail(f"invalid provenance file {path.name}")
    return value


def prepare(repo: Path, artifact_dir: Path, platform: str, target: str) -> None:
    if artifact_dir.exists():
        fail("artifact directory already exists")
    lock = repo / "Cargo.lock"
    if not lock.is_file():
        fail("resolved Cargo.lock is missing")
    require_clean_tracked_source(repo)
    artifact_dir.mkdir(parents=True)
    state = {
        "schema": 1,
        "platform": platform,
        "target": target,
        "source_head": git(repo, "rev-parse", "HEAD"),
        "source_tree": git(repo, "rev-parse", "HEAD^{tree}"),
        "tracked_source_sha256": tracked_source_sha256(repo),
        "cargo_lock_sha256": sha256(lock),
    }
    write_json(artifact_dir / STATE, state)


def verify_checkout(repo: Path, state: dict[str, object]) -> None:
    require_clean_tracked_source(repo)
    expected = {
        "source_head": git(repo, "rev-parse", "HEAD"),
        "source_tree": git(repo, "rev-parse", "HEAD^{tree}"),
        "tracked_source_sha256": tracked_source_sha256(repo),
        "cargo_lock_sha256": sha256(repo / "Cargo.lock"),
    }
    for key, actual in expected.items():
        if state.get(key) != actual:
            fail(f"{key} changed after dependency resolution")


def required_binary_names(target: str) -> set[str]:
    suffix = ".exe" if "windows" in target else ""
    return {f"x0x{suffix}", f"x0xd{suffix}"}


def current_build_binaries(messages_path: Path, release_dir: Path, target: str) -> list[Path]:
    observed: set[str] = set()
    build_finished = False
    cargo_records_started = False
    try:
        lines = messages_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"build messages are unavailable: {type(error).__name__}")
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # `cross` invokes the pinned host rustup toolchain before Cargo.
            # Rustup writes this one status line to stdout (optionally with
            # SGR colour), so it is captured by the workflow's `tee` ahead of
            # Cargo's JSON stream. Accept only that exact pinned status and
            # only before the first Cargo record; every other non-JSON line
            # remains fatal.
            if (
                not cargo_records_started
                and RUSTUP_CROSS_PREAMBLE.fullmatch(ANSI_SGR.sub("", line)) is not None
            ):
                continue
            fail(f"invalid Cargo build record at line {line_number}")
        if not isinstance(record, dict):
            fail(f"invalid Cargo build record at line {line_number}")
        cargo_records_started = True
        reason = record.get("reason")
        if reason == "build-finished":
            if build_finished or record.get("success") is not True:
                fail("Cargo build did not finish successfully")
            build_finished = True
            continue
        if reason != "compiler-artifact":
            continue
        artifact_target = record.get("target")
        if not isinstance(artifact_target, dict):
            fail("compiler artifact target is invalid")
        kinds = artifact_target.get("kind")
        executable = record.get("executable")
        if not isinstance(kinds, list) or "bin" not in kinds or executable is None:
            continue
        if not isinstance(executable, str) or not executable:
            fail("compiler artifact executable is invalid")
        fresh = record.get("fresh")
        if not isinstance(fresh, bool):
            fail("compiler artifact freshness is invalid")
        executable_path = (
            PureWindowsPath(executable) if "windows" in target else PurePosixPath(executable)
        )
        name = executable_path.name
        if (
            Path(name).name != name
            or not name.startswith("x0x")
            or Path(name).suffix in {".d", ".pdb"}
        ):
            continue
        expected_target_name = artifact_target.get("name")
        expected_suffix = ".exe" if "windows" in target else ""
        if not isinstance(expected_target_name, str) or name != expected_target_name + expected_suffix:
            fail("compiler artifact executable does not match its bin target")
        if name in observed:
            fail(f"duplicate current binary artifact: {name}")
        observed.add(name)
    if not build_finished:
        fail("Cargo build completion record is missing")
    missing = required_binary_names(target) - observed
    if missing:
        fail(f"required binary is missing: {sorted(missing)[0]}")
    binaries = [release_dir / name for name in sorted(observed)]
    for path in binaries:
        if not path.is_file():
            fail(f"current binary output is missing: {path.name}")
    return binaries


def finalize(repo: Path, artifact_dir: Path, release_dir: Path, messages_path: Path) -> None:
    state_path = artifact_dir / STATE
    state = read_json(state_path)
    target = state.get("target")
    if not isinstance(target, str) or not target:
        fail("provenance target is missing")
    verify_checkout(repo, state)

    binaries = []
    for source in current_build_binaries(messages_path, release_dir, target):
        name = source.name
        destination = artifact_dir / name
        if destination.exists():
            fail(f"staged binary already exists: {name}")
        shutil.copy2(source, destination)
        if sha256(source) != sha256(destination):
            fail(f"staged binary changed while copying: {name}")
        binaries.append(
            {"file": name, "sha256": sha256(destination), "size": destination.stat().st_size}
        )

    lock_destination = artifact_dir / "Cargo.lock"
    shutil.copy2(repo / "Cargo.lock", lock_destination)
    if sha256(lock_destination) != state.get("cargo_lock_sha256"):
        fail("staged Cargo.lock does not match resolved dependency graph")
    manifest = {
        **state,
        "cargo_build_messages_sha256": sha256(messages_path),
        "cargo_lock_file": "Cargo.lock",
        "binaries": binaries,
    }
    write_json(artifact_dir / MANIFEST, manifest)
    state_path.unlink()
    verify_artifact(artifact_dir)


def verify_artifact(artifact_dir: Path) -> None:
    manifest = read_json(artifact_dir / MANIFEST)
    lock_name = manifest.get("cargo_lock_file")
    if lock_name != "Cargo.lock":
        fail("manifest Cargo.lock path is invalid")
    if sha256(artifact_dir / lock_name) != manifest.get("cargo_lock_sha256"):
        fail("artifact Cargo.lock hash mismatch")
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list):
        fail("manifest binaries are invalid")
    required_names = required_binary_names(str(manifest.get("target", "")))
    observed_names: set[str] = set()
    for entry in binaries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            fail("invalid binary manifest entry")
        name = entry["file"]
        if (
            name in observed_names
            or not name.startswith("x0x")
            or Path(name).name != name
            or Path(name).suffix in {".d", ".pdb"}
        ):
            fail("unexpected or duplicate binary in manifest")
        path = artifact_dir / name
        if not path.is_file():
            fail(f"artifact binary is missing: {name}")
        if path.stat().st_size != entry.get("size") or sha256(path) != entry.get("sha256"):
            fail(f"artifact binary hash mismatch: {name}")
        observed_names.add(name)
    if not required_names.issubset(observed_names):
        fail("artifact does not contain both required binaries")
    allowed = {MANIFEST, "Cargo.lock", *observed_names}
    actual = {path.name for path in artifact_dir.iterdir()}
    if actual != allowed:
        fail("artifact directory contains unexpected files")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repo", type=Path, required=True)
    prepare_parser.add_argument("--artifact-dir", type=Path, required=True)
    prepare_parser.add_argument("--platform", required=True)
    prepare_parser.add_argument("--target", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--repo", type=Path, required=True)
    finalize_parser.add_argument("--artifact-dir", type=Path, required=True)
    finalize_parser.add_argument("--release-dir", type=Path, required=True)
    finalize_parser.add_argument("--build-messages", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--artifact-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "prepare":
            prepare(args.repo.resolve(), args.artifact_dir.resolve(), args.platform, args.target)
        elif args.command == "finalize":
            finalize(
                args.repo.resolve(),
                args.artifact_dir.resolve(),
                args.release_dir.resolve(),
                args.build_messages.resolve(),
            )
        else:
            verify_artifact(args.artifact_dir.resolve())
    except (OSError, RuntimeError) as error:
        print(f"provenance error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
