#!/usr/bin/env python3
"""Release-boundary regression checks; never authenticate or upload a crate."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.load((ROOT / ".github/workflows/publish.yml").read_text(), Loader=yaml.BaseLoader)
PUBLISH = WORKFLOW["jobs"]["publish"]


def run_step(name):
    return next(step["run"] for step in PUBLISH["steps"] if step["name"] == name)


class ReleaseBoundary(unittest.TestCase):
    def test_permissions_and_fresh_commit(self):
        self.assertNotIn("id-token", WORKFLOW["permissions"])
        validate = WORKFLOW["jobs"]["validate"]
        self.assertNotIn("id-token", validate["permissions"])
        self.assertNotIn("environment", validate)
        self.assertEqual(PUBLISH["needs"], "validate")
        self.assertEqual(PUBLISH["environment"], "crates-io")
        self.assertEqual(PUBLISH["permissions"]["id-token"], "write")
        for job in (validate, PUBLISH):
            checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
            self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
            self.assertEqual(checkout["with"]["persist-credentials"], "false")
        self.assertEqual(PUBLISH["env"]["RUSTUP_TOOLCHAIN"], "${{ needs.validate.outputs.rust_version }}")
        self.assertEqual(PUBLISH["env"]["CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS"], "cargo:token")
        self.assertIn("CARGO_HOME=%s/release-cargo-home", run_step("Prepare the validated toolchain and reject repository Cargo hooks"))
        for step in PUBLISH["steps"]:
            self.assertNotIn("cache", step.get("uses", ""))
            self.assertNotIn("download-artifact", step.get("uses", ""))
            for line in step.get("run", "").splitlines():
                if line.strip().startswith("cargo "):
                    self.assertIn("--no-verify", line)
                    self.assertIn("--locked", line)
                    self.assertIn(line.split()[1], ("package", "publish"))
        steps = PUBLISH["steps"]
        digest_index = next(i for i, s in enumerate(steps) if "EXPECTED_SHA256" in s.get("env", {}))
        auth_index = next(i for i, s in enumerate(steps) if s.get("id") == "auth")
        self.assertEqual(auth_index, digest_index + 1)
        self.assertEqual(auth_index + 1, len(steps) - 1)
        self.assertEqual(steps[-1]["run"], "cargo publish --no-verify --locked")
        self.assertEqual(steps[-1]["env"]["CARGO_REGISTRY_TOKEN"], "${{ steps.auth.outputs.token }}")

    def test_digest_gate(self):
        command = run_step("Match the package to the validated digest without building")
        expected = hashlib.sha256(b"verified package").hexdigest()
        for digest, allowed in ((expected, True), ("0" * 64, False), ("", False), ("bad\nvalue", False)):
            with self.subTest(digest=digest), tempfile.TemporaryDirectory(dir=os.environ.get("RELEASE_TEST_TMPDIR")) as tmp:
                root = Path(tmp)
                tools = root / "bin"
                tools.mkdir()
                cargo = tools / "cargo"
                cargo.write_text("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" > cargo-called\nmkdir -p target/package\nprintf 'verified package' > target/package/attestation-verify-0.1.0.crate\n")
                cargo.chmod(0o755)
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], RELEASE_TAG="v0.1.0", EXPECTED_SHA256=digest)
                result = subprocess.run(["bash", "-c", command + "\ntouch auth-reached"], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                self.assertEqual((root / "auth-reached").exists(), allowed)
                if digest not in (expected, "0" * 64):
                    self.assertFalse((root / "cargo-called").exists())
                else:
                    self.assertEqual((root / "cargo-called").read_text().strip(), "package --no-verify --locked")

    def test_repository_cargo_hooks_rejected(self):
        command = run_step("Prepare the validated toolchain and reject repository Cargo hooks")
        for config in (None, "config", "config.toml", "broken-symlink"):
            with self.subTest(config=config), tempfile.TemporaryDirectory(dir=os.environ.get("RELEASE_TEST_TMPDIR")) as tmp:
                root = Path(tmp)
                tools = root / "bin"
                tools.mkdir()
                rustup = tools / "rustup"
                rustup.write_text("#!/bin/sh\ntouch toolchain-installed\n")
                rustup.chmod(0o755)
                if config:
                    (root / ".cargo").mkdir()
                    if config == "broken-symlink":
                        (root / ".cargo/config.toml").symlink_to("missing-config")
                    else:
                        (root / ".cargo" / config).write_text('[registry]\nglobal-credential-providers = ["malicious-helper"]\n')
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], RUSTUP_TOOLCHAIN="1.97.1", RUNNER_TEMP=tmp, GITHUB_ENV=str(root / "github-env"))
                result = subprocess.run(["bash", "-c", command], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, config is None, result.stderr)
                self.assertEqual((root / "toolchain-installed").exists(), config is None)

    def test_cargo_no_verify_does_not_execute_build_script(self):
        # Real Cargo, a dependency-free fixture, and a build script that fails
        # whenever executed. --dry-run prevents any registry upload.
        with tempfile.TemporaryDirectory(dir=os.environ.get("RELEASE_TEST_TMPDIR")) as tmp:
            root = Path(tmp) / "fixture"
            shutil.copytree(ROOT / "scripts/test-fixtures/release-boundary", root)
            env = dict(os.environ)
            for key in list(env):
                if key.startswith("CARGO_REGISTR") or key.startswith("ACTIONS_ID_TOKEN"):
                    del env[key]
            env["CARGO_HOME"] = str(Path(tmp) / "cargo-home")
            def cargo(*args):
                return subprocess.run(["cargo", *args], cwd=root, env=env, capture_output=True, text=True)
            result = cargo("generate-lockfile", "--offline")
            self.assertEqual(result.returncode, 0, result.stderr)
            result = cargo("package", "--locked", "--offline")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build script executed", result.stderr)
            result = cargo("package", "--no-verify", "--locked", "--offline")
            self.assertEqual(result.returncode, 0, result.stderr)
            archive = root / "target/package/release-boundary-fixture-0.0.0.crate"
            expected = archive.read_bytes()
            # A local Git registry avoids network access or real registry
            # credentials. Its upload endpoint is a closed loopback port.
            index = Path(tmp) / "registry"
            shutil.copytree(ROOT / "scripts/test-fixtures/release-registry", index)
            for args in (("init", "-q"), ("add", "config.json"),
                         ("-c", "user.name=Release fixture", "-c", "user.email=fixture@example.invalid",
                          "-c", "commit.gpgsign=false", "commit", "-qm", "Initialize fixture registry")):
                subprocess.run(["git", *args], cwd=index, check=True, capture_output=True)
            result = cargo("publish", "--dry-run", "--no-verify", "--locked", "--index", index.as_uri())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(archive.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
