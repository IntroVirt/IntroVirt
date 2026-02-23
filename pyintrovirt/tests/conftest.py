"""Pytest configuration for pyintrovirt tests.

Tests require the IntroVirt Python bindings (introvirt module). If the bindings
are not installed or not on PYTHONPATH, the entire test directory is skipped.
"""

import pytest

pytest.importorskip("introvirt")
