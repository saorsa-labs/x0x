#!/usr/bin/env python3
"""Fail-closed custody checks for staged x0x release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

LOCK_MANIFEST = "release-lock.json"
PROVENANCE = "build-provenance.json"
PLATFORM_TARGETS = {
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
    "linux-x64-musl": "x86_64-unknown-linux-musl",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "macos-x64": "x86_64-apple-darwin",
    "macos-arm64": "aarch64-apple-darwin",
    "windows-x64": "x86_64-pc-windows-msvc",
}
PLATFORMS = set(PLATFORM_TARGETS)


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        fail(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid {path.name}: {type(error).__name__}")
    if not isinstance(value, dict):
        fail(f"invalid {path.name}")
    return value


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_identity(repo: Path) -> dict[str, str]:
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        fail("tracked source differs from checkout")
    return {
        "source_head": git(repo, "rev-parse", "HEAD"),
        "source_tree": git(repo, "rev-parse", "HEAD^{tree}"),
    }


def resolve(repo: Path, output: Path) -> None:
    if output.exists():
        fail("lock custody output already exists")
    lock = repo / "Cargo.lock"
    if not lock.is_file():
        fail("resolved Cargo.lock is missing")
    output.mkdir(parents=True)
    shutil.copy2(lock, output / "Cargo.lock")
    save(output / LOCK_MANIFEST, {
        "schema": 1,
        **source_identity(repo),
        "cargo_lock_sha256": digest(lock),
    })


def verify_lock(repo: Path, custody: Path, install: bool) -> dict[str, object]:
    manifest = load(custody / LOCK_MANIFEST)
    if manifest.get("schema") != 1:
        fail("unsupported lock custody schema")
    for key, value in source_identity(repo).items():
        if manifest.get(key) != value:
            fail(f"{key} does not match release lock custody")
    lock = custody / "Cargo.lock"
    if not lock.is_file() or digest(lock) != manifest.get("cargo_lock_sha256"):
        fail("release Cargo.lock hash mismatch")
    if set(path.name for path in custody.iterdir()) != {"Cargo.lock", LOCK_MANIFEST}:
        fail("unexpected file in lock custody")
    if install:
        shutil.copy2(lock, repo / "Cargo.lock")
        if digest(repo / "Cargo.lock") != manifest["cargo_lock_sha256"]:
            fail("installed Cargo.lock hash mismatch")
    return manifest


def archive_members(archive: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive, "r:gz") as source:
            entries = source.getmembers()
            for entry in entries:
                if entry.name in seen:
                    fail(f"duplicate archive member path: {entry.name}")
                seen.add(entry.name)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    fail(f"non-regular archive member: {entry.name}")
                stream = source.extractfile(entry)
                if stream is None:
                    fail("archive member is unreadable")
                result[entry.name] = stream.read()
    elif archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            for entry in source.infolist():
                if entry.filename in seen:
                    fail(f"duplicate archive member path: {entry.filename}")
                seen.add(entry.filename)
                if entry.is_dir():
                    continue
                mode = entry.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind and kind != stat.S_IFREG:
                    fail(f"non-regular archive member: {entry.filename}")
                result[entry.filename] = source.read(entry)
    else:
        fail(f"unsupported release archive: {archive.name}")
    for name in result:
        path = PurePosixPath(name.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            fail("unsafe archive member path")
    return result


def verify_archive(archive: Path, lock_manifest: dict[str, object]) -> dict[str, object]:
    members = archive_members(archive)
    manifests = [(name, data) for name, data in members.items() if PurePosixPath(name).name == PROVENANCE]
    if len(manifests) != 1:
        fail("archive must contain exactly one build provenance manifest")
    try:
        provenance = json.loads(manifests[0][1])
    except json.JSONDecodeError:
        fail("archive build provenance is invalid")
    if not isinstance(provenance, dict):
        fail("archive build provenance is invalid")
    for key in ("source_head", "source_tree", "cargo_lock_sha256"):
        if provenance.get(key) != lock_manifest.get(key):
            fail(f"archive {key} differs from release custody")
    platform = provenance.get("platform")
    if platform not in PLATFORMS:
        fail("archive platform identity mismatch")
    extension = "zip" if platform == "windows-x64" else "tar.gz"
    if archive.name != f"x0x-{platform}.{extension}":
        fail("archive canonical name mismatch")
    if provenance.get("target") != PLATFORM_TARGETS[platform]:
        fail("archive target identity mismatch")
    lock_members = [(name, data) for name, data in members.items() if PurePosixPath(name).name == "Cargo.lock"]
    if len(lock_members) != 1 or hashlib.sha256(lock_members[0][1]).hexdigest() != lock_manifest.get("cargo_lock_sha256"):
        fail("archive Cargo.lock does not match release custody")
    binaries = provenance.get("binaries")
    if not isinstance(binaries, list):
        fail("archive binary provenance is invalid")
    observed: set[str] = set()
    for entry in binaries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            fail("archive binary provenance entry is invalid")
        name = entry["file"]
        candidates = [data for path, data in members.items() if PurePosixPath(path).name == name]
        if len(candidates) != 1:
            fail(f"archive binary is missing or duplicated: {name}")
        data = candidates[0]
        if len(data) != entry.get("size") or hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            fail(f"archive binary hash mismatch: {name}")
        observed.add(name)
    suffix = ".exe" if platform == "windows-x64" else ""
    if not {f"x0x{suffix}", f"x0xd{suffix}"}.issubset(observed):
        fail("archive does not contain both required binaries")
    allowed = {"Cargo.lock", PROVENANCE, "README.md", *observed}
    for member in members:
        name = PurePosixPath(member).name
        if name not in allowed and not name.startswith("LICENSE"):
            fail(f"unexpected packaged file: {name}")
    return provenance


def aggregate(custody: Path, artifacts: Path, output: Path) -> None:
    lock_manifest = load(custody / LOCK_MANIFEST)
    lock = custody / "Cargo.lock"
    if not lock.is_file() or digest(lock) != lock_manifest.get("cargo_lock_sha256"):
        fail("aggregate Cargo.lock custody mismatch")
    archives = sorted([*artifacts.glob("release-*/*.tar.gz"), *artifacts.glob("release-*/*.zip")])
    records = []
    platforms: set[str] = set()
    for archive in archives:
        checksum = archive.with_name(f"{archive.name}.sha256")
        if not checksum.is_file():
            fail(f"archive checksum is missing: {archive.name}")
        fields = checksum.read_text(encoding="utf-8").split()
        if len(fields) != 2 or fields[0] != digest(archive) or Path(fields[1]).name != archive.name:
            fail(f"archive checksum mismatch: {archive.name}")
        provenance = verify_archive(archive, lock_manifest)
        platform = str(provenance["platform"])
        if platform in platforms:
            fail(f"duplicate release platform: {platform}")
        platforms.add(platform)
        records.append({"platform": platform, "archive": archive.name, "sha256": digest(archive)})
    if platforms != PLATFORMS:
        fail(f"release platform set mismatch: {sorted(PLATFORMS - platforms)}")
    save(output, {"schema": 1, **lock_manifest, "archives": records})


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("resolve"); p.add_argument("--repo", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("install-lock"); p.add_argument("--repo", type=Path, required=True); p.add_argument("--custody", type=Path, required=True)
    p = commands.add_parser("aggregate"); p.add_argument("--custody", type=Path, required=True); p.add_argument("--artifacts", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "resolve": resolve(args.repo.resolve(), args.output.resolve())
        elif args.command == "install-lock": verify_lock(args.repo.resolve(), args.custody.resolve(), True)
        else: aggregate(args.custody.resolve(), args.artifacts.resolve(), args.output.resolve())
    except (OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"release custody error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
