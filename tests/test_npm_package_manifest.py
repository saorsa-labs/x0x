import json
import unittest
from pathlib import Path


class NpmPackageManifestTest(unittest.TestCase):
    def test_declared_entrypoints_are_in_npm_files_whitelist(self):
        package_root = Path(__file__).resolve().parents[1]
        package_json = json.loads((package_root / "package.json").read_text())

        files = set(package_json["files"])
        for field in ("main", "types"):
            entrypoint = package_json[field]
            self.assertIn(entrypoint, files)
            self.assertTrue((package_root / entrypoint).is_file())


if __name__ == "__main__":
    unittest.main()
