#!/usr/bin/python
# coding=utf-8
"""
Disk tools bridge for binary analysis.

Wraps system tools available on the analysis host (objdump, readelf, strings)
to augment LIEF-based binary analysis with direct tool output. Falls back
gracefully if a tool is not installed.

Tools used:
  readelf  — extended ELF section/segment/note/dependency info
  objdump  — disassembly around flagged import addresses
  strings  — multi-encoding string extraction from raw binary
  nuclei   — tech fingerprinting and vuln scanning for backend URLs
  naabu    — port discovery on backend hosts
"""
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_TIMEOUT = 30


def _find_tool(name: str, env_var: str, *fallback_dirs: str) -> str:
    """Find a tool: env override → PATH → common user dirs → bare name."""
    if os.environ.get(env_var):
        return os.environ[env_var]
    found = shutil.which(name)
    if found:
        return found
    home = Path.home()
    for d in fallback_dirs:
        p = home / d / name
        if p.is_file():
            return str(p)
    return name  # let subprocess raise FileNotFoundError naturally


READELF = _find_tool('readelf', 'READELF_BIN')
OBJDUMP = _find_tool('objdump', 'OBJDUMP_BIN')
STRINGS = _find_tool('strings', 'STRINGS_BIN')
NUCLEI  = _find_tool('nuclei',  'NUCLEI_BIN',  'go/bin', '.local/bin')
NAABU   = _find_tool('naabu',   'NAABU_BIN',   'go/bin', '.local/bin')


def _run(cmd: list[str], timeout: int = _TIMEOUT) -> str:
    """Run a command and return stdout as a string. Empty string on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug('%s failed: %s', cmd[0], e)
        return ''


# ── readelf ──────────────────────────────────────────────────────────────────

def readelf_dynamic(binary_path: str) -> dict:
    """
    Extract dynamic linking info from an ELF binary using readelf.

    Returns:
        {
            "shared_libs": [str],      # DT_NEEDED entries
            "rpath": [str],            # DT_RPATH / DT_RUNPATH (rpath injection risk)
            "has_relro": bool,         # PT_GNU_RELRO segment
            "has_bindnow": bool,       # DT_FLAGS BIND_NOW
            "interpreter": str,        # PT_INTERP path
        }
    """
    result = {
        'shared_libs': [],
        'rpath': [],
        'has_relro': False,
        'has_bindnow': False,
        'interpreter': '',
    }
    out = _run([READELF, '-d', '-W', binary_path])
    for line in out.splitlines():
        if '(NEEDED)' in line:
            m = re.search(r'\[([^\]]+)\]', line)
            if m:
                result['shared_libs'].append(m.group(1))
        elif '(RPATH)' in line or '(RUNPATH)' in line:
            m = re.search(r'\[([^\]]+)\]', line)
            if m:
                result['rpath'].append(m.group(1))
        elif '(FLAGS)' in line and 'BIND_NOW' in line:
            result['has_bindnow'] = True
        elif '(FLAGS_1)' in line and 'NOW' in line:
            result['has_bindnow'] = True

    out_prog = _run([READELF, '-W', '-l', binary_path])
    for line in out_prog.splitlines():
        if 'GNU_RELRO' in line:
            result['has_relro'] = True
        if 'Requesting program interpreter' in line or 'interpreter' in line.lower():
            m = re.search(r':\s*(.+?)\]', line)
            if m:
                result['interpreter'] = m.group(1).strip()

    return result


def readelf_notes(binary_path: str) -> dict:
    """
    Extract ELF GNU_PROPERTY notes (Intel CET IBT/SHSTK) using readelf.
    Returns a summary dict with reliable pattern matching on readelf -n output.
    """
    out = _run([READELF, '-W', '-n', binary_path])
    result = {
        'has_ibt': False,
        'has_shstk': False,
        'build_id': '',
        'abi_tag': '',
    }
    for line in out.splitlines():
        line_l = line.lower()
        # Intel CET IBT: appears as "IBT" in GNU_PROPERTY lines
        if re.search(r'\bibt\b', line, re.IGNORECASE):
            result['has_ibt'] = True
        # Shadow Stack
        if 'shstk' in line_l or 'shadow stack' in line_l:
            result['has_shstk'] = True
        # Build ID
        m = re.search(r'Build ID:\s+([0-9a-f]{20,})', line, re.IGNORECASE)
        if m:
            result['build_id'] = m.group(1)
        # OS/ABI tag
        m = re.search(r'OS/ABI:\s+(\S+)', line)
        if m:
            result['abi_tag'] = m.group(1)
    return result


def readelf_symbols_dangerous(binary_path: str, dangerous: list[str]) -> list[str]:
    """
    Use readelf to list dynamic symbol imports and intersect with a danger list.
    Faster than loading with LIEF for quick checks.
    """
    danger_set = set(dangerous)
    out = _run([READELF, '-W', '--dyn-syms', binary_path])
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        sym = parts[-1].split('@')[0]
        if sym in danger_set:
            found.append(sym)
    return list(dict.fromkeys(found))


# ── strings ──────────────────────────────────────────────────────────────────

def extract_strings(binary_path: str, min_len: int = 6) -> list[str]:
    """
    Extract printable strings from a binary using the system strings tool.
    Uses both little-endian 16-bit (for .NET/Windows) and standard encoding.
    Returns deduplicated list.
    """
    out = _run([STRINGS, f'-n{min_len}', binary_path])
    wide = _run([STRINGS, '-e', 'l', f'-n{min_len}', binary_path])
    combined = set(out.splitlines()) | set(wide.splitlines())
    return [s for s in combined if s.strip()]


# ── objdump ───────────────────────────────────────────────────────────────────

def objdump_imports(binary_path: str) -> list[dict]:
    """
    Extract import table from a binary using objdump.
    Works for both ELF and PE files.
    Returns list of {"name": str, "library": str} dicts.
    """
    out = _run([OBJDUMP, '-p', binary_path])
    imports = []
    if 'DLL Name:' in out:
        current_dll = ''
        for line in out.splitlines():
            if 'DLL Name:' in line:
                m = re.search(r'DLL Name:\s+(.+)', line)
                if m:
                    current_dll = m.group(1).strip()
            elif 'Symbol:' in line:
                m = re.search(r'Symbol:\s+(.+)', line)
                if m:
                    imports.append({'name': m.group(1).strip(), 'library': current_dll})
        return imports
    out_dyn = _run([OBJDUMP, '-T', binary_path])
    for line in out_dyn.splitlines():
        if 'UND' in line:
            parts = line.split()
            if parts:
                sym = parts[-1].split('@')[0]
                if sym and not sym.startswith('_'):
                    imports.append({'name': sym, 'library': ''})
    return imports


# ── nuclei backend scan ───────────────────────────────────────────────────────

def nuclei_scan_urls(
    urls: list[str],
    templates: list[str] | None = None,
    timeout: int = 60,
) -> list[dict]:
    """
    Run nuclei against a list of URLs extracted from an app binary.
    Defaults to tech-detect + exposure templates — safe, read-only, no active exploits.

    Args:
        urls:      list of URLs to scan
        templates: nuclei template tags (default: ['tech-detect', 'exposures'])
        timeout:   command timeout in seconds

    Returns:
        list of {"url": str, "template": str, "severity": str, "info": dict} findings
    """
    if not urls or not (shutil.which('nuclei') or Path(NUCLEI).is_file()):
        return []
    if templates is None:
        templates = ['tech-detect', 'exposures']

    url_file = None
    findings = []
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write('\n'.join(urls))
            url_file = tf.name
        cmd = [NUCLEI, '-l', url_file, '-json', '-silent', '-no-color']
        for tag in templates:
            cmd.extend(['-tags', tag])
        out = _run(cmd, timeout=timeout)
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                findings.append({
                    'url': item.get('host') or item.get('url', ''),
                    'template': item.get('template-id') or item.get('templateID', ''),
                    'severity': item.get('info', {}).get('severity', 'info'),
                    'name': item.get('info', {}).get('name', ''),
                    'info': item.get('info', {}),
                })
            except Exception:
                continue
    finally:
        if url_file:
            Path(url_file).unlink(missing_ok=True)

    return findings


# ── naabu port scan ───────────────────────────────────────────────────────────

def naabu_port_scan(hosts: list[str], ports: str = '80,443,8080,8443,8888,9000') -> list[dict]:
    """
    Run naabu port scan on backend hosts extracted from an app.
    Returns list of {"host": str, "port": int, "ip": str} open ports.
    """
    if not hosts or not (shutil.which('naabu') or Path(NAABU).is_file()):
        return []

    host_file = None
    results = []
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write('\n'.join(hosts))
            host_file = tf.name
        cmd = [NAABU, '-l', host_file, '-p', ports, '-json', '-silent', '-no-color']
        out = _run(cmd, timeout=60)
        for line in out.splitlines():
            try:
                item = json.loads(line)
                results.append({
                    'host': item.get('host', ''),
                    'port': item.get('port', 0),
                    'ip': item.get('ip', ''),
                })
            except Exception:
                continue
    finally:
        if host_file:
            Path(host_file).unlink(missing_ok=True)

    return results
