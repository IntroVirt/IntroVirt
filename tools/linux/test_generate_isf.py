#!/usr/bin/env python3
"""Tests for tools/linux/generate_isf.py. No guest required."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import generate_isf


def _vol3(drop_symbol=None, drop_member=None):
    symbols = {
        name: {"address": 0x1000 + index}
        for index, name in enumerate(
            generate_isf.REQUIRED_SYMBOLS + generate_isf.OPTIONAL_SYMBOLS
        )
    }
    if drop_symbol:
        symbols.pop(drop_symbol, None)

    user_types = {}
    for struct, members in generate_isf.REQUIRED_TYPES.items():
        fields = {}
        for index, member in enumerate(members):
            if drop_member == (struct, member):
                continue
            fields[member] = {"offset": index * 8, "type": {"kind": "int"}}
        user_types[struct] = {"size": 256, "fields": fields}

    return {
        "metadata": {"arch": "x86_64", "producer": {"name": "test"}},
        "symbols": symbols,
        "user_types": user_types,
    }


class GenerateIsfTest(unittest.TestCase):
    def test_check_accepts_complete_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps(_vol3()))
            result = subprocess.run(
                [sys.executable, str(Path(generate_isf.__file__)), "--in", str(src), "--check"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_check_rejects_missing_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps(_vol3(drop_symbol="init_task")))
            result = subprocess.run(
                [sys.executable, str(Path(generate_isf.__file__)), "--in", str(src), "--check"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing symbol: init_task", result.stderr)

    def test_check_rejects_missing_required_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps(_vol3(drop_member=("task_struct", "pid"))))
            result = subprocess.run(
                [sys.executable, str(Path(generate_isf.__file__)), "--in", str(src), "--check"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing member: task_struct.pid", result.stderr)

    def test_out_writes_sectepe_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            dst = Path(tmp) / "out.json"
            src.write_text(json.dumps(_vol3()))
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(generate_isf.__file__)),
                    "--in",
                    str(src),
                    "--out",
                    str(dst),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            profile = json.loads(dst.read_text())
            self.assertEqual(profile["format"], "sectepe-linux-isf/1")
            self.assertIn("init_task", profile["symbols"])
            self.assertEqual(profile["types"]["task_struct"]["pid"], 8)
            self.assertEqual(profile["sizes"]["task_struct"], 256)


if __name__ == "__main__":
    unittest.main()
