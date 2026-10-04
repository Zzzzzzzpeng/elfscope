from pathlib import Path

import pytest

pytest.importorskip("elftools")

from elfscope.analysis import _entropy, _extract_strings


def test_entropy_empty():
    assert _entropy(b"") == 0.0


def test_entropy_uniform_byte():
    assert _entropy(b"A" * 128) == 0.0


def test_entropy_two_symbols():
    value = _entropy(b"AB" * 128)
    assert 0.99 < value < 1.01


def test_strings(tmp_path: Path):
    sample = tmp_path / "blob.bin"
    sample.write_bytes(b"abc short\x00This is a useful string\x00another string here\x00")
    values = _extract_strings(sample, minimum=6, limit=10)
    assert "This is a useful string" in values
    assert "another string here" in values
