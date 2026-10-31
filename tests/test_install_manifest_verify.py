#!/usr/bin/env python3
"""Regression tests for the signed-manifest gate in scripts/install.sh (#1355).

The installers must verify the ML-DSA-65 release manifest exactly as the
updater does, and refuse to install on a bad or missing signature. The verify
path under test is the real one: the fake release's x0x delegates the
--verify-release-manifest probe to a fixture binary compiled from
src/upgrade/signature.rs itself (the pattern of tests/upgrade_test_signing.rs),
with a compile-time test key replacing the production key through the
debug-only upgrade-test-signing seam.

The fixture build is cached under the repo target directory, keyed by a hash
of its sources; the cached throwaway signing key never leaves that directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
SIGNATURE_RS = ROOT / "src" / "upgrade" / "signature.rs"
PLATFORM = "linux-x64-gnu"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"

# Minimal PATH: everything install.sh needs, and no host gpg, so the GPG
# branch never runs against fixture files it cannot check.
TEST_PATH_SUFFIX = "/usr/bin:/bin"

FIXTURE_MAIN_RS = """#[allow(dead_code)]
#[path = "{signature_rs}"]
mod signature;

use saorsa_pqc::api::sig::ml_dsa_65;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, a, b] if cmd == "keygen" => keygen(a, b),
        [cmd, a, b, c] if cmd == "sign" => sign(a, b, c),
        [cmd, a, b] if cmd == "verify" => verify(a, b),
        _ => Err("usage: keygen PUB SEC | sign MANIFEST SEC SIG | verify MANIFEST SIG".to_string()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn keygen(public_path: &str, secret_path: &str) -> Result<(), String> {
    let dsa = ml_dsa_65();
    let (public, secret) = dsa.generate_keypair().map_err(|e| e.to_string())?;
    std::fs::write(public_path, public.to_bytes()).map_err(|e| e.to_string())?;
    std::fs::write(secret_path, secret.to_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

fn sign(manifest_path: &str, secret_path: &str, signature_path: &str) -> Result<(), String> {
    let secret = std::fs::read(secret_path).map_err(|e| e.to_string())?;
    let manifest = std::fs::read(manifest_path).map_err(|e| e.to_string())?;
    let signature = signature::sign_with_context(&secret, &manifest).map_err(|e| e.to_string())?;
    std::fs::write(signature_path, signature).map_err(|e| e.to_string())?;
    Ok(())
}

fn verify(manifest_path: &str, signature_path: &str) -> Result<(), String> {
    let manifest = std::fs::read(manifest_path).map_err(|e| e.to_string())?;
    let signature = std::fs::read(signature_path).map_err(|e| e.to_string())?;
    signature::verify_manifest_signature(&manifest, &signature).map_err(|e| e.to_string())
}
"""

FIXTURE_BUILD_RS = """fn main() {
    println!("cargo:rerun-if-changed=public-key.bin");
    // Only the upgrade-test-signing build embeds a key; the keygen stage
    // builds before public-key.bin exists.
    if std::env::var_os("CARGO_FEATURE_UPGRADE_TEST_SIGNING").is_some() {
        let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        std::fs::copy("public-key.bin", output.join("upgrade-test-signing-public-key.bin")).unwrap();
    }
}
"""

FIXTURE_CARGO_TOML = """[package]
name = "install-manifest-fixture"
version = "0.0.0"
edition = "2021"
[workspace]
[features]
upgrade-test-signing = []
[dependencies]
saorsa-pqc = "0.5"
thiserror = "2.0"
tracing = "0.1"
"""


def target_root() -> Path:
    env_dir = os.environ.get("CARGO_TARGET_DIR")
    return Path(env_dir) if env_dir else ROOT / "target"


def cargo_output_dir(root: Path) -> Path:
    """Where cargo puts this fixture's binaries. A global ~/.cargo/config.toml
    build.target-dir (all agent worktrees share one dir) wins over the
    default <crate>/target, so resolve it instead of guessing."""
    env_dir = os.environ.get("CARGO_TARGET_DIR")
    if env_dir:
        return Path(env_dir) / "debug"
    config = Path.home() / ".cargo" / "config.toml"
    if config.exists():
        import tomllib

        with config.open("rb") as handle:
            configured = tomllib.load(handle).get("build", {}).get("target-dir")
        if configured:
            return Path(configured).expanduser() / "debug"
    return root / "target" / "debug"


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def build_fixture() -> tuple[Path, Path]:
    """Compile the manifest signing/verification fixture and return
    (binary, secret-key) paths. Cached per source hash. The key pair is a
    throwaway fixture key, never a release key."""
    sources = {
        "Cargo.toml": FIXTURE_CARGO_TOML,
        "build.rs": FIXTURE_BUILD_RS,
        "main.rs": FIXTURE_MAIN_RS.replace("{signature_rs}", str(SIGNATURE_RS)),
    }
    digest = hashlib.sha256(
        b"\0".join(
            sources[name].encode() + SIGNATURE_RS.read_bytes() for name in sorted(sources)
        )
    ).hexdigest()[:16]
    root = target_root() / "install-test-fixture" / digest
    binary = cargo_output_dir(root) / "install-manifest-fixture"
    public = root / "public-key.bin"
    secret = root / "test-signing-secret.bin"
    # The stamp is written only after the feature build; without it, a
    # half-finished cache could serve the stage-1 binary, which embeds the
    # production key and would refuse every fixture signature.
    stamp = root / ".feature-build-done"
    if stamp.exists() and binary.exists() and public.exists() and secret.exists():
        return binary, secret

    root.mkdir(parents=True, exist_ok=True)
    for name, contents in sources.items():
        target = root / "src" / name if name == "main.rs" else root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    # Reuse the reviewed dependency graph; resolution changes stay local.
    shutil.copy(ROOT / "Cargo.lock", root / "Cargo.lock")

    # cargo-llvm-cov and other wrappers must not leak into the nested build.
    scrub = [
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_SHOW_ENV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_BUILD_TARGET",
    ]
    env = {k: v for k, v in os.environ.items() if k not in scrub}

    def cargo(*args: str) -> None:
        build = subprocess.run(
            ["cargo", "build", "--manifest-path", str(root / "Cargo.toml"), *args],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if build.returncode != 0:
            raise AssertionError(f"fixture build failed ({args}):\n{build.stderr}")

    # Stage 1: keygen needs no embedded key. Stage 2 embeds the generated
    # public key through the debug-only upgrade-test-signing seam, so verify
    # trusts exactly the fixture key pair.
    cargo("--offline")
    subprocess.run(
        [binary, "keygen", str(public), str(secret)],
        check=True,
        cwd=root,
        timeout=60,
    )
    cargo("--offline", "--features", "upgrade-test-signing")
    stamp.write_text("ok", encoding="utf-8")
    return binary, secret


def manifest_bytes(
    archive_sha256: str, target: str = TARGET_TRIPLE, compact: bool = False
) -> bytes:
    """A release manifest in the published layout (pretty-printed, or
    compact-serialized to prove the parser does not depend on whitespace)."""
    return json.dumps(
        {
            "schema_version": 1,
            "version": "0.0.0-test",
            "timestamp": 0,
            "assets": [
                {
                    "target": target,
                    "archive_url": "http://fixtures/archive",
                    "archive_sha256": archive_sha256,
                    "signature_url": "http://fixtures/archive.sig",
                }
            ],
            "skill_url": "",
            "skill_sha256": "0" * 64,
        },
        indent=None if compact else 2,
        separators=(",", ":") if compact else None,
    ).encode()


class InstallManifestVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("cargo") is None:
            raise unittest.SkipTest("cargo is required to build the manifest fixture")
        try:
            cls.verifier, cls.secret = build_fixture()
        except AssertionError as error:
            # A cold cargo cache (no saorsa-pqc in the registry cache) cannot
            # build the fixture offline; the gate still runs wherever the
            # workspace has been built once.
            raise unittest.SkipTest(f"manifest fixture unavailable: {error}") from error

    def sign(self, manifest: bytes, tmp: Path, secret: Path | None = None) -> bytes:
        scratch = tmp / "signing"
        scratch.mkdir(exist_ok=True)
        manifest_path = scratch / "release-manifest.json"
        signature_path = scratch / "release-manifest.json.sig"
        manifest_path.write_bytes(manifest)
        subprocess.run(
            [
                str(self.verifier),
                "sign",
                str(manifest_path),
                str(secret or self.secret),
                str(signature_path),
            ],
            check=True,
            timeout=60,
        )
        return signature_path.read_bytes()

    def keygen(self, tmp: Path) -> Path:
        """A second throwaway key pair, for signatures the verifier must
        reject."""
        scratch = tmp / "keys"
        scratch.mkdir(exist_ok=True)
        secret = scratch / "other-secret.bin"
        subprocess.run(
            [str(self.verifier), "keygen", str(scratch / "other.pub"), str(secret)],
            check=True,
            timeout=60,
        )
        return secret

    def run_installer(
        self,
        tmp: Path,
        manifest: bytes | Callable[[str], bytes] | None,
        *,
        served_manifest: bytes | Callable[[str], bytes] | None = None,
        missing: frozenset[str] = frozenset(),
        secret: Path | None = None,
        archive_probe_delegates: bool = True,
    ) -> tuple[int, str, Path, Path]:
        """Build a fake release, serve it through a fake curl, run install.sh
        in a scratch HOME, and return (rc, combined output, probe-calls log,
        install bin dir).

        `manifest` is either fixed bytes or a factory that receives the fake
        archive's real SHA-256 (the good path needs the manifest to name it).
        `served_manifest` overrides the bytes the server returns after
        `manifest` was signed (the tamper case). `missing` names release
        files the fake downloads fail on. `secret` signs with another
        throwaway key (the wrong-key case). With
        `archive_probe_delegates=False` the release's x0x accepts any
        manifest, isolating the installed-verifier preference. The manifest
        signature is real: signed by the fixture key the verifier binary
        embeds."""
        fake_bin = tmp / "fake-bin"
        archive_dir = tmp / "archive" / f"x0x-{PLATFORM}"
        home = tmp / "home"
        files_dir = tmp / "files"
        archive = tmp / f"x0x-{PLATFORM}.tar.gz"
        probe_calls = tmp / "probe-calls.log"
        fake_bin.mkdir(exist_ok=True)
        archive_dir.mkdir(parents=True, exist_ok=True)
        home.mkdir(exist_ok=True)
        files_dir.mkdir(exist_ok=True)

        write_executable(
            fake_bin / "uname",
            '#!/usr/bin/env sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n',
        )

        write_executable(
            archive_dir / "x0xd",
            '#!/usr/bin/env sh\n'
            'DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"\n'
            'mkdir -p "$DIR"\n'
            'printf \'%s\\n\' "127.0.0.1:65535" > "$DIR/api.port"\n',
        )
        # The release's x0x: the probe delegates to the real verifier binary
        # (or accepts anything, when the test isolates the installed one).
        probe_branch = (
            f'    exec "{self.verifier}" verify "$2" "$3"\n'
            if archive_probe_delegates
            else "    exit 0\n"
        )
        write_executable(
            archive_dir / "x0x",
            "#!/usr/bin/env sh\n"
            'if [ "$1" = "--verify-release-manifest" ]; then\n'
            '    printf \'%s\\n\' probe >> "$PROBE_CALLS"\n'
            f"{probe_branch}"
            "fi\n"
            "exit 0\n",
        )

        with tarfile.open(archive, "w:gz") as tar:
            tar.add(archive_dir / "x0xd", arcname=f"x0x-{PLATFORM}/x0xd")
            tar.add(archive_dir / "x0x", arcname=f"x0x-{PLATFORM}/x0x")

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        served = {
            archive.name: archive.read_bytes(),
            f"{archive.name}.sha256": f"{digest}  {archive.name}\n".encode(),
        }
        if manifest is not None:
            if callable(manifest):
                manifest = manifest(digest)
            if served_manifest is not None:
                if callable(served_manifest):
                    served_manifest = served_manifest(digest)
                served["release-manifest.json"] = served_manifest
            else:
                served["release-manifest.json"] = manifest
            served["release-manifest.json.sig"] = self.sign(manifest, tmp, secret)
        for name, data in served.items():
            (files_dir / name).write_bytes(data)

        missing_patterns = "".join(
            f"        *{name}) echo 'download failed: {name}' >&2; exit 22 ;;\n"
            for name in sorted(missing)
        )
        serve = "".join(
            f"        *{name}) cat \"{files_dir / name}\" > \"$OUT\"; exit 0 ;;\n"
            for name in sorted(served)
        )
        write_executable(
            fake_bin / "curl",
            f"""#!/usr/bin/env sh
OUT=""
URL=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) shift; OUT="$1" ;;
        http*) URL="$1" ;;
    esac
    shift
done
if [ -n "$OUT" ]; then
    case "$URL" in
{missing_patterns}{serve}        *) exit 1 ;;
    esac
fi
case "$URL" in
    */health) printf '%s\\n' '{{"ok":true}}' ;;
    *) exit 1 ;;
esac
""",
        )

        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "XDG_DATA_HOME": str(tmp / "data"),
                "PATH": f"{fake_bin}{os.pathsep}{TEST_PATH_SUFFIX}",
                "TMPDIR": str(tmp),
                "PROBE_CALLS": str(probe_calls),
            }
        )
        result = subprocess.run(
            ["sh", str(INSTALL_SH)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
        output = result.stdout + result.stderr
        return result.returncode, output, probe_calls, home / ".local" / "bin"

    def assert_refused(
        self,
        rc: int,
        output: str,
        bin_dir: Path,
        probe_calls: Path,
        *needles: str,
        probe_ran: bool = True,
        probe_log: list[str] | None = None,
    ) -> None:
        self.assertNotEqual(rc, 0, output)
        for needle in needles:
            self.assertIn(needle, output)
        self.assertNotIn("Installed:", output)
        self.assertNotIn("Starting:", output)
        self.assertFalse((bin_dir / "x0x").exists())
        self.assertFalse((bin_dir / "x0xd").exists())
        calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
        expected = probe_log if probe_log is not None else (["probe"] if probe_ran else [])
        self.assertEqual(calls, expected)

    def test_good_signed_manifest_installs(self) -> None:
        for layout in ("pretty", "compact"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as tmpdir:
                rc, output, probe_calls, bin_dir = self.run_installer(
                    Path(tmpdir),
                    lambda digest, compact=layout == "compact": manifest_bytes(
                        digest, compact=compact
                    ),
                )
                self.assertEqual(rc, 0, output)
                self.assertIn("Archive hash matches the manifest entry", output)
                self.assertIn("ML-DSA-65 manifest signature verified", output)
                self.assertIn("Installed:", output)
                self.assertTrue((bin_dir / "x0x").exists())
                self.assertEqual(
                    probe_calls.read_text(encoding="utf-8").splitlines(), ["probe"]
                )

    # name, manifest (None/bytes/factory), served override, missing release
    # files, expected output needles, whether the probe gets to run at all,
    # and an alternate signing key (None = the fixture key). probe_ran=False
    # pins that the gate refused before any archive byte executed; True pins
    # that the probe itself rejected the manifest.
    REFUSAL_CASES = [
        # Signed over the real hash, but different bytes are served: the
        # tampering is caught by the signature, after the binding passes.
        (
            "tampered_manifest",
            manifest_bytes,
            lambda digest: manifest_bytes(digest).replace(b"0.0.0-test", b"9.9.9-evil"),
            (),
            ("failed ML-DSA signature verification",),
            True,
            "wrong_key",
        ),
        # Valid signature naming another archive's hash: refused by the hash
        # binding, before extraction.
        (
            "manifest_names_another_archive",
            manifest_bytes("4" * 64),
            None,
            (),
            ("does not match the manifest entry",),
            False,
            None,
        ),
        (
            "missing_manifest",
            None,
            None,
            ("release-manifest.json",),
            ("download failed", "release-manifest.json"),
            False,
            None,
        ),
        (
            "missing_signature",
            manifest_bytes("0" * 64),
            None,
            ("release-manifest.json.sig",),
            ("download failed", "release-manifest.json.sig"),
            False,
            None,
        ),
        # Correctly signed manifest with no linux-x64-gnu asset: the hash
        # lookup fails closed, before extraction.
        (
            "manifest_without_platform_entry",
            manifest_bytes("0" * 64, target="aarch64-unknown-linux-gnu"),
            None,
            (),
            ("no archive_sha256 entry for x86_64-unknown-linux-gnu",),
            False,
            None,
        ),
    ]

    def test_bad_releases_are_refused(self) -> None:
        for name, manifest, served, missing, needles, probe_ran, key in self.REFUSAL_CASES:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                secret = self.keygen(tmp) if key == "wrong_key" else None
                rc, output, probe_calls, bin_dir = self.run_installer(
                    tmp,
                    manifest,
                    served_manifest=served,
                    missing=frozenset(missing),
                    secret=secret,
                )
                self.assert_refused(
                    rc, output, bin_dir, probe_calls, *needles, probe_ran=probe_ran
                )

    def test_installed_verifier_is_preferred_and_its_refusal_blocks_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir = tmp / "home" / ".local" / "bin"
            bin_dir.mkdir(parents=True)
            # An installed, probe-capable x0x that really verifies; the
            # release's own x0x is lenient (accepts any manifest). The
            # installer must use the installed one, so a manifest signed by
            # the wrong key is refused even though the downloaded binary
            # would have accepted it.
            write_executable(
                bin_dir / "x0x",
                "#!/usr/bin/env sh\n"
                'if [ "$1" = "--upgrade-probe" ]; then\n'
                '    printf \'%s\\n\' \'{"version":"0.48.1"}\'\n'
                "    exit 0\n"
                "fi\n"
                'if [ "$1" = "--verify-release-manifest" ]; then\n'
                '    printf \'%s\\n\' installed-probe >> "$PROBE_CALLS"\n'
                f'    exec "{self.verifier}" verify "$2" "$3"\n'
                "fi\n"
                "exit 0\n",
            )
            installed_x0x = (bin_dir / "x0x").read_bytes()
            rc, output, probe_calls, bin_dir = self.run_installer(
                tmp,
                manifest_bytes,
                secret=self.keygen(tmp),
                archive_probe_delegates=False,
            )
            self.assertNotEqual(rc, 0, output)
            self.assertIn("failed ML-DSA signature verification", output)
            self.assertNotIn("Installed:", output)
            # Nothing was installed over the existing binary.
            self.assertEqual((bin_dir / "x0x").read_bytes(), installed_x0x)
            self.assertFalse((bin_dir / "x0xd").exists())
            self.assertEqual(
                probe_calls.read_text(encoding="utf-8").splitlines(),
                ["installed-probe"],
            )


if __name__ == "__main__":
    unittest.main()
