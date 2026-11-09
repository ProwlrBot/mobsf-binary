#!/usr/bin/python
# coding=utf-8
"""
Path safety guards ported from mobile-ide evidence.rs / findings.rs.

Three independent utilities:
  validate_scan_hash(h)        — rejects any hash that isn't a 32-char hex string
                                 before it is joined to UPLD_DIR.
  validate_evidence_path(root, rel) — guards analyst-supplied relative paths
                                      against traversal, null bytes, and prefix
                                      escape before any file operation.
  guard_file_size(path, limit) — raises ValueError for files exceeding limit
                                 bytes so callers never stream unbounded files.

None of these touch the filesystem beyond stat() / resolve(); callers own I/O.
"""
import re
from pathlib import Path

_MD5_RE = re.compile(r'^[0-9a-f]{32}$')

MAX_EVIDENCE_BYTES: int = 200 * 1024 * 1024  # 200 MB — mirrors mobile-ide

ALLOWED_EVIDENCE_PREFIXES = frozenset([
    'evidence/screenshots',
    'evidence/recordings',
    'evidence/logcat',
    'findings',
    'recon',
    'reports',
])


def validate_scan_hash(h: str) -> str:
    """
    Validate a scan hash before joining it to UPLD_DIR.

    Accepts exactly 32 lowercase hex characters.  Raises ValueError for
    anything else — including path separators, dotdot, and mixed case.

    Returns the validated hash unchanged.
    """
    if not isinstance(h, str) or not _MD5_RE.match(h):
        raise ValueError(f'Invalid scan hash: {h!r}')
    return h


def validate_evidence_path(root: Path, rel: str) -> Path:
    """
    Validate a relative evidence file path supplied by an analyst or API caller.

    Guards (ported from mobile-ide findings.rs validate_evidence_file_path):
      1. Backslash normalisation
      2. Absolute path rejection
      3. Dotdot component detection
      4. Null-byte detection
      5. Allowed-prefix whitelist (ALLOWED_EVIDENCE_PREFIXES)
      6. Double-canonicalise: resolved path must still be under root

    Args:
        root: absolute base directory (e.g. UPLD_DIR / scan_hash)
        rel:  caller-supplied relative path string

    Returns:
        Resolved absolute Path guaranteed to live under root.

    Raises:
        ValueError with a human-readable reason on any guard failure.
    """
    if '\0' in rel:
        raise ValueError('path contains null byte')

    normalised = rel.replace('\\', '/')
    p = Path(normalised)

    if p.is_absolute():
        raise ValueError('path must be relative')

    if any(part == '..' for part in p.parts):
        raise ValueError('path contains dotdot component')

    # Allowed-prefix whitelist
    rel_str = str(p)
    if not any(rel_str.startswith(pfx) for pfx in ALLOWED_EVIDENCE_PREFIXES):
        raise ValueError(f'path not under an allowed prefix: {rel_str!r}')

    resolved = (root / p).resolve()
    root_resolved = root.resolve()

    # Double-canonicalize: reject symlink escapes
    if not str(resolved).startswith(str(root_resolved) + '/') and resolved != root_resolved:
        raise ValueError('path escapes project root after resolution')

    return resolved


def guard_file_size(path: Path, limit: int = MAX_EVIDENCE_BYTES) -> None:
    """
    Raise ValueError if path is larger than limit bytes.

    Call before opening a file for streaming to avoid OOM from large artifacts.
    Does not open the file — only stat().

    Args:
        path:  absolute Path to check
        limit: max allowed bytes (default 200 MB)

    Raises:
        ValueError if the file exceeds limit or cannot be stat'd.
    """
    try:
        size = path.stat().st_size
    except OSError as e:
        raise ValueError(f'cannot stat {path}: {e}') from e
    if size > limit:
        raise ValueError(
            f'{path.name} is {size // (1024*1024)} MB — '
            f'exceeds {limit // (1024*1024)} MB limit'
        )
