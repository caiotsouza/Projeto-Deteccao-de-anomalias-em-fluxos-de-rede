"""Arquivos sinteticos: tamanhos, hashes e protecao contra sobrescrita."""

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from lab_tools.prepare_http_payloads import PAYLOADS, prepare


class LabHttpPayloadTests(unittest.TestCase):
    def test_exact_sizes_hashes_and_no_overwrite(self):
        root = Path(__file__).resolve().parents[1]
        (root / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root / "tmp") as temporary:
            target = Path(temporary) / "benign-v1"
            report = prepare(target)
            self.assertEqual(len(report["files"]), 3)
            for item in report["files"]:
                content = (target / item["name"]).read_bytes()
                self.assertEqual(len(content), PAYLOADS[item["name"]])
                self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
            self.assertEqual(json.loads((target / "payload_manifest.json").read_text()), report)
            with self.assertRaises(FileExistsError):
                prepare(target)
            self.assertEqual(json.loads((target / "payload_manifest.json").read_text()), report)

    @unittest.skipUnless(shutil.which("powershell.exe"), "Requer Windows PowerShell para testar os mocks")
    def test_powershell_scenarios_guards_logging_and_fail_fast_with_mocks(self):
        root = Path(__file__).resolve().parents[1]
        (root / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root / "tmp") as temporary:
            result = subprocess.run([
                shutil.which("powershell.exe"), "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(root / "tests/test_benign_http_script.ps1"),
                "-OutputRoot", str(Path(temporary) / "logs"),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("mocked requests only", result.stdout)


if __name__ == "__main__":
    unittest.main()
