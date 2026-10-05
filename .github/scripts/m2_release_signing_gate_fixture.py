#!/usr/bin/env python3
"""Prepare public M2 controls once on Linux without compiling the x0x graph."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

from m2_release_signing_gate import digest, production_fixture

HELPER_MANIFEST = '''[package]
name = "m2-signing-fixture"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
fips204 = { version = "=0.4.6", default-features = false, features = ["ml-dsa-65", "default-rng"] }

[profile.dev]
opt-level = 1
'''

# Only public bytes leave this process. The throwaway secret exists in memory
# and is dropped before the artifact is uploaded; no release key is accessed.
HELPER_SOURCE = '''use fips204::{ml_dsa_65, traits::{SerDes, Signer, Verifier}};
use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(std::env::args_os().nth(1).ok_or("missing output directory")?);
    let manifest = std::fs::read(directory.join("release-manifest.json"))?;
    let (public, secret) = ml_dsa_65::try_keygen()?;
    let signature = secret.try_sign(&manifest, b"x0x-release-v1")?;
    if !public.verify(&manifest, &signature, b"x0x-release-v1") {
        return Err("throwaway signature failed own-key positive control".into());
    }
    let mut changed = manifest.clone();
    changed.push(0);
    if public.verify(&changed, &signature, b"x0x-release-v1") {
        return Err("throwaway signature accepted changed manifest".into());
    }
    std::fs::write(directory.join("throwaway.pub"), public.into_bytes())?;
    std::fs::write(directory.join("throwaway.sig"), signature)?;
    Ok(())
}
'''


def write_helper(helper, repo):
    helper.mkdir(parents=True, exist_ok=True)
    (helper / "src").mkdir(exist_ok=True)
    (helper / "Cargo.toml").write_text(HELPER_MANIFEST)
    (helper / "src/main.rs").write_text(HELPER_SOURCE)
    shutil.copyfile(repo / "Cargo.lock", helper / "Cargo.lock")


def verify_helper_lock(helper, repo):
    """Allow pruning the copied lock, but no dependency version/checksum drift."""
    original = tomllib.loads((repo / "Cargo.lock").read_text())["package"]
    allowed = {(row["name"], row["version"], row.get("source"), row.get("checksum"))
               for row in original}
    resolved = tomllib.loads((helper / "Cargo.lock").read_text())["package"]
    for row in resolved:
        if row["name"] == "m2-signing-fixture" and row.get("source") is None:
            continue
        if (row["name"], row["version"], row.get("source"), row.get("checksum")) not in allowed:
            raise ValueError("fixture dependency differs from committed Cargo.lock")


def prepare(output, helper, repo):
    if not sys.platform.startswith("linux"):
        raise ValueError("signing control generation requires Linux")
    output.mkdir(parents=True)  # Refuse to reuse stale controls.
    for name, data in production_fixture().items():
        (output / name).write_bytes(data)
    write_helper(helper, repo)
    env = dict(os.environ)
    for key in ("CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
                "LLVM_PROFILE_FILE"):
        env.pop(key, None)
    env["CARGO_TARGET_DIR"] = str(helper / "target")
    # Normalize only workspace entries in the copied lock, preserving locked
    # dependencies. A copied x0x lock cannot pass --locked until this helper's
    # package is recorded. Reject dependency drift before metadata or build.
    subprocess.run(["cargo", "update", "--workspace", "--manifest-path",
                    str(helper / "Cargo.toml")], env=env, check=True)
    verify_helper_lock(helper, repo)
    # A cold exact-key cache may need to fetch locked registry sources.
    subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                    "--manifest-path", str(helper / "Cargo.toml")],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["cargo", "build", "--locked", "--manifest-path",
                    str(helper / "Cargo.toml")], env=env, check=True)
    subprocess.run([str(helper / "target/debug/m2-signing-fixture"), str(output)],
                   env=env, check=True, timeout=90)
    files = {path.name: digest(path.read_bytes()) for path in output.iterdir()}
    receipt = {"schema": 1, "result": "PASS", "own_key_verified": True,
               "algorithm": "ML-DSA-65", "context": "x0x-release-v1", "sha256": files,
               "helper_lock_sha256": digest((helper / "Cargo.lock").read_bytes())}
    for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        receipt[key] = os.environ[key]
    raw = (json.dumps(receipt, indent=2) + "\n").encode()
    (output / "receipt.json").write_bytes(raw)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("receipt_sha256=" + digest(raw) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.output.resolve(), args.helper.resolve(), Path(__file__).resolve().parents[2])


if __name__ == "__main__":
    main()
