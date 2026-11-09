"""Tests for evidence_path path traversal guards."""
import tempfile
from pathlib import Path

import pytest

from mobsf.StaticAnalyzer.views.common.evidence_path import (
    MAX_EVIDENCE_BYTES,
    guard_file_size,
    validate_evidence_path,
    validate_scan_hash,
)


# ── validate_scan_hash ────────────────────────────────────────────────────────

def test_valid_md5_accepted():
    h = 'a' * 32
    assert validate_scan_hash(h) == h


def test_valid_md5_hex_chars_accepted():
    h = '0123456789abcdef' * 2
    assert validate_scan_hash(h) == h


def test_hash_too_short_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('a' * 31)


def test_hash_too_long_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('a' * 33)


def test_hash_uppercase_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('A' * 32)


def test_hash_path_separator_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('a' * 16 + '/' + 'b' * 15)


def test_hash_dotdot_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('../' + 'a' * 29)


def test_hash_empty_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash('')


def test_hash_non_string_rejected():
    with pytest.raises(ValueError, match='Invalid scan hash'):
        validate_scan_hash(None)  # type: ignore[arg-type]


# ── validate_evidence_path ────────────────────────────────────────────────────

def test_valid_path_accepted(tmp_path):
    target = tmp_path / 'findings' / 'report.json'
    target.parent.mkdir(parents=True)
    target.touch()
    result = validate_evidence_path(tmp_path, 'findings/report.json')
    assert result == target.resolve()


def test_screenshots_prefix_accepted(tmp_path):
    target = tmp_path / 'evidence' / 'screenshots' / 'shot.png'
    target.parent.mkdir(parents=True)
    target.touch()
    result = validate_evidence_path(tmp_path, 'evidence/screenshots/shot.png')
    assert result == target.resolve()


def test_dotdot_rejected(tmp_path):
    with pytest.raises(ValueError, match='dotdot'):
        validate_evidence_path(tmp_path, 'findings/../../../etc/passwd')


def test_absolute_path_rejected(tmp_path):
    with pytest.raises(ValueError, match='relative'):
        validate_evidence_path(tmp_path, '/etc/passwd')


def test_null_byte_rejected(tmp_path):
    with pytest.raises(ValueError, match='null byte'):
        validate_evidence_path(tmp_path, 'findings/file\x00.json')


def test_unallowed_prefix_rejected(tmp_path):
    with pytest.raises(ValueError, match='allowed prefix'):
        validate_evidence_path(tmp_path, 'secrets/token.txt')


def test_backslash_normalised(tmp_path):
    target = tmp_path / 'evidence' / 'logcat' / 'run.log'
    target.parent.mkdir(parents=True)
    target.touch()
    result = validate_evidence_path(tmp_path, 'evidence\\logcat\\run.log')
    assert result == target.resolve()


# ── guard_file_size ───────────────────────────────────────────────────────────

def test_small_file_passes(tmp_path):
    f = tmp_path / 'small.bin'
    f.write_bytes(b'x' * 1024)
    guard_file_size(f)  # should not raise


def test_large_file_raises(tmp_path):
    f = tmp_path / 'big.bin'
    f.write_bytes(b'x' * (MAX_EVIDENCE_BYTES + 1))
    with pytest.raises(ValueError, match='exceeds'):
        guard_file_size(f)


def test_custom_limit(tmp_path):
    f = tmp_path / 'medium.bin'
    f.write_bytes(b'x' * 1024)
    with pytest.raises(ValueError, match='exceeds'):
        guard_file_size(f, limit=512)


def test_missing_file_raises():
    with pytest.raises(ValueError, match='cannot stat'):
        guard_file_size(Path('/nonexistent/path/file.bin'))
