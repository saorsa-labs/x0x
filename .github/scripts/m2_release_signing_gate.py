#!/usr/bin/env python3
"""ADR 0094: prove production trust on the exact archived daemon and CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import tarfile
import tempfile
import zipfile

from build_artifact_provenance import ANSI_SGR, RUSTUP_CROSS_PREAMBLE, verify_artifact

PRODUCTION_FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/upgrade/v0.46.3"
PRODUCTION_FILES = {
    "release-manifest.json": "4770cb72da68f232abc164a7b20035217b99b64ff157faa333dbb729786b84c0",
    "release-manifest.json.sig": "5927a8f8705ad543155ebe5b301463a5d9ec3941fc6670559c1c2e6c1dbc6aea",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def production_features(messages):
    """Missing/malformed features, profiles, targets or completion fail closed."""
    observed = {}
    started = finished = False
    for line in messages.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            if not started and RUSTUP_CROSS_PREAMBLE.fullmatch(ANSI_SGR.sub("", line)):
                continue
            raise ValueError("invalid Cargo build record") from None
        started = True
        if not isinstance(row, dict) or finished:
            raise ValueError("invalid Cargo build stream")
        if row.get("reason") == "build-finished":
            if row.get("success") is not True:
                raise ValueError("release build failed")
            finished = True
        if row.get("reason") != "compiler-artifact":
            continue
        features = row.get("features")
        if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
            raise ValueError("missing Cargo feature evidence")
        if "upgrade-test-signing" in features:
            raise ValueError("release includes upgrade-test-signing")
        target = row.get("target", {})
        if target.get("kind") != ["bin"] or target.get("name") not in ("x0x", "x0xd"):
            continue
        profile = row.get("profile")
        if not isinstance(profile, dict) or profile.get("debug_assertions") is not False:
            raise ValueError("release binary retains debug assertions")
        executable = row.get("executable")
        if not isinstance(executable, str) or not executable:
            raise ValueError("missing release executable")
        name = target["name"]
        if PureWindowsPath(executable).name not in (name, name + ".exe"):
            raise ValueError("release executable disagrees with target")
        if name in observed:
            raise ValueError("duplicate release binary evidence")
        observed[name] = features
    if not finished or set(observed) != {"x0x", "x0xd"}:
        raise ValueError("incomplete release binary evidence")
    return observed


def archived_binaries(archive, destination, custody):
    verify_artifact(custody)
    manifest = json.loads((custody / "build-provenance.json").read_text())
    suffix = ".exe" if "windows" in manifest["target"] else ""
    required = {name + suffix for name in ("x0x", "x0xd")}
    expected = {row["file"]: row["sha256"] for row in manifest["binaries"]}
    contents = {}
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            for row in package.infolist():
                name = PurePosixPath(row.filename).name
                if name in required:
                    if name in contents or row.is_dir():
                        raise ValueError("duplicate or non-file archived binary")
                    contents[name] = package.read(row)
    else:
        with tarfile.open(archive, "r:gz") as package:
            for row in package.getmembers():
                name = PurePosixPath(row.name).name
                if name in required:
                    if name in contents or not row.isfile():
                        raise ValueError("duplicate or non-file archived binary")
                    with package.extractfile(row) as source:
                        contents[name] = source.read()
    if set(contents) != required:
        raise ValueError("archive lacks both packaged binaries")
    for name, data in contents.items():
        if digest(data) != expected[name]:
            raise ValueError("archived binary differs from build custody")
        path = destination / name
        path.write_bytes(data)
        path.chmod(0o700)
    return {name: digest(data) for name, data in contents.items()}


def production_fixture():
    """Read committed original bytes; never depend on live release downloads."""
    contents = {name: (PRODUCTION_FIXTURE / name).read_bytes() for name in PRODUCTION_FILES}
    if any(digest(data) != PRODUCTION_FILES[name] for name, data in contents.items()):
        raise ValueError("pinned production fixture changed")
    return contents


def control_fixture(directory, receipt_sha256, destination, receipt):
    """Bind the once-generated positive control to its producer's job output."""
    raw = (directory / "receipt.json").read_bytes()
    if digest(raw) != receipt_sha256:
        raise ValueError("control fixture receipt differs from producer output")
    evidence = json.loads(raw)
    if (evidence.get("schema") != 1 or evidence.get("result") != "PASS"
            or evidence.get("own_key_verified") is not True
            or evidence.get("context") != "x0x-release-v1"
            or evidence.get("algorithm") != "ML-DSA-65"):
        raise ValueError("control fixture lacks successful own-key verification")
    for key in ("GITHUB_SHA", "GITHUB_RUN_ID"):
        if key in os.environ and evidence.get(key) != os.environ[key]:
            raise ValueError("control fixture belongs to another workflow execution")
    if "GITHUB_RUN_ATTEMPT" in os.environ:
        # Re-running failed legs reuses a successful producer from an earlier
        # attempt. Its job-output digest, run ID and SHA still bind the bundle.
        try:
            producer_attempt = int(evidence.get("GITHUB_RUN_ATTEMPT", ""))
            current_attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
        except (TypeError, ValueError):
            raise ValueError("control fixture has invalid workflow attempt") from None
        if not 1 <= producer_attempt <= current_attempt:
            raise ValueError("control fixture belongs to another workflow execution")
    required = set(PRODUCTION_FILES) | {"throwaway.pub", "throwaway.sig"}
    if set(evidence.get("sha256", {})) != required:
        raise ValueError("control fixture has incomplete file evidence")
    if {path.name for path in directory.iterdir()} != required | {"receipt.json"}:
        raise ValueError("control fixture contains missing or unexpected files")
    committed = production_fixture()
    for name in sorted(required):
        data = (directory / name).read_bytes()
        if digest(data) != evidence["sha256"][name]:
            raise ValueError("control fixture bytes differ from producer evidence")
        if name in committed and data != committed[name]:
            raise ValueError("control fixture differs from committed production fixture")
        if name in ("throwaway.pub", "throwaway.sig") and len(data) != (
                1952 if name.endswith(".pub") else 3309):
            raise ValueError("control fixture has invalid ML-DSA-65 size")
        (destination / name).write_bytes(data)
    receipt["production_fixture"] = {"path": "tests/fixtures/upgrade/v0.46.3",
                                     "sha256": PRODUCTION_FILES}
    receipt["control_fixture_receipt_sha256"] = receipt_sha256
    receipt["throwaway_public_sha256"] = evidence["sha256"]["throwaway.pub"]
    receipt["throwaway_signature_sha256"] = evidence["sha256"]["throwaway.sig"]
    receipt["throwaway_own_key_verified"] = True


def bound_build_messages(messages, custody):
    verify_artifact(custody)
    manifest = json.loads((custody / "build-provenance.json").read_text())
    observed = digest(messages.read_bytes())
    if observed != manifest.get("cargo_build_messages_sha256"):
        raise ValueError("build messages differ from build custody")
    return observed


def require_control(result, expected, name, label):
    if result.returncode != expected or (
        expected == 1 and b"signature is invalid" not in result.stderr
    ):
        tail = result.stderr[-2048:].decode("utf-8", "replace")
        raise ValueError(f"packaged {name} {label} control failed: "
                         f"exit {result.returncode}, stderr tail: {tail!r}")


def packaged(args, receipt):
    if args.platform not in ("linux-x64-gnu", "linux-x64-musl", "linux-arm64-gnu",
                             "macos-x64", "macos-arm64", "windows-x64"):
        raise ValueError("unsupported packaged execution platform")
    receipt["build_messages_sha256"] = bound_build_messages(args.build_messages, args.custody)
    receipt["features"] = production_features(args.build_messages)
    receipt["archive_sha256"] = digest(args.archive.read_bytes())
    with tempfile.TemporaryDirectory(prefix="m2-packaged-signing-") as temp:
        root = Path(temp).resolve()
        binaries = root / "binaries"
        binaries.mkdir()
        receipt["binaries"] = archived_binaries(args.archive, binaries, args.custody)
        control_fixture(args.control_fixture, args.control_receipt_sha256, root, receipt)
        foreign = root / "throwaway.sig"
        prefix = []
        if args.platform == "linux-arm64-gnu":
            prefix = ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"]
        elif args.platform == "macos-x64":
            prefix = ["/usr/bin/arch", "-x86_64"]
        receipt["execution_prefix"] = prefix
        cwd = root / "empty-cwd"
        home = root / "empty-home"
        cwd.mkdir()
        home.mkdir()
        env = dict(os.environ, HOME=str(home), X0X_HOME=str(home), USERPROFILE=str(home),
                   APPDATA=str(home), LOCALAPPDATA=str(home), XDG_DATA_HOME=str(home),
                   XDG_CONFIG_HOME=str(home), XDG_CACHE_HOME=str(home))
        receipt["controls"] = []
        for name, before in receipt["binaries"].items():
            binary = binaries / name
            for label, signature, expected in (
                ("production", root / "release-manifest.json.sig", 0),
                ("throwaway", foreign, 1),
            ):
                result = subprocess.run(prefix + [str(binary), "--verify-release-manifest",
                    str(root / "release-manifest.json"), str(signature)],
                    cwd=cwd, env=env, capture_output=True, timeout=90)
                receipt["controls"].append({"binary": name, "control": label,
                    "exit": result.returncode, "expected": expected,
                    "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
                require_control(result, expected, name, label)
                if any(cwd.iterdir()) or any(home.iterdir()) or digest(binary.read_bytes()) != before:
                    raise ValueError("inert verification changed application files")
        receipt["inert_files_unchanged"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-messages", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--control-fixture", type=Path, required=True)
    parser.add_argument("--control-receipt-sha256", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    receipt = {"schema": 1, "platform": args.platform, "result": "FAIL"}
    try:
        packaged(args, receipt)
        receipt["result"] = "PASS"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
