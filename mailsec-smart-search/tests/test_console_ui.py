"""Run the dependency-free JavaScript console routing regression harness."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_source_aware_console_routing():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    root = Path(__file__).resolve().parent.parent
    subprocess.run([node, "--check", str(root / "src/mailsec_smart_search/static/console.js")],
                   check=True, cwd=root)
    subprocess.run([node, str(root / "tests/console_ui_test.cjs")], check=True, cwd=root)
