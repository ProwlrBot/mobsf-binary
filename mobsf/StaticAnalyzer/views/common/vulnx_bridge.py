#!/usr/bin/python
# coding=utf-8
"""
VulnX bridge for tech-stack CVE lookup.

When MobSF's fingerprinting detects a library or framework version, this
module queries ProjectDiscovery's vulnx CLI to surface CVEs with exploit
and CISA-KEV metadata — providing richer exploit-awareness than the
OSV.dev module which focuses on exact versioned package matches.

vulnx must be in PATH. If not installed or not authenticated, the module
degrades gracefully and returns empty results without crashing.

Install / auth: https://docs.projectdiscovery.io/tools/vulnx
"""
import json
import logging
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

VULNX_BIN = shutil.which('vulnx') or '/home/anon/go/bin/vulnx'
VULNX_TIMEOUT = 20
MAX_RESULTS_PER_QUERY = 20

SEVERITY_MAP = {
    'critical': 'high',
    'high':     'high',
    'medium':   'warning',
    'low':      'info',
    'info':     'info',
    'unknown':  'info',
}


def _vulnx_available() -> bool:
    """Check if vulnx binary exists and is executable."""
    return bool(shutil.which('vulnx') or (VULNX_BIN and __import__('os').path.isfile(VULNX_BIN)))


def _run_vulnx(args: list[str]) -> list[dict] | None:
    """
    Run vulnx with the given args and return parsed JSON results.
    Returns None on timeout or error; empty list if no results.
    """
    if not _vulnx_available():
        return None
    cmd = [VULNX_BIN, '--json', '--silent'] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=VULNX_TIMEOUT,
        )
        if result.returncode != 0:
            logger.debug('vulnx exit %d: %s', result.returncode, result.stderr[:200])
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        # vulnx --json outputs one JSON object per line or a JSON array
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, list):
                    items.extend(obj)
                else:
                    items.append(obj)
            except json.JSONDecodeError:
                continue
        return items
    except subprocess.TimeoutExpired:
        logger.warning('vulnx timed out after %ds', VULNX_TIMEOUT)
        return []
    except FileNotFoundError:
        logger.debug('vulnx binary not found at %s', VULNX_BIN)
        return None
    except Exception as e:
        logger.warning('vulnx error: %s', e)
        return []


def _parse_vuln(raw: dict) -> dict:
    """Normalize a vulnx JSON result into a MobSF-compatible finding."""
    cve_id = raw.get('id') or raw.get('cve_id') or raw.get('ID') or ''
    severity_raw = (raw.get('severity') or raw.get('cvss_severity') or 'unknown').lower()
    cvss = 0.0
    try:
        cvss = float(raw.get('cvss_score') or raw.get('cvss') or raw.get('cvssScore') or 0)
    except (ValueError, TypeError):
        pass
    is_kev = bool(raw.get('is_kev') or raw.get('cisa_kev') or raw.get('kev'))
    has_poc = bool(raw.get('poc') or raw.get('has_poc') or raw.get('exploit_available'))
    epss = 0.0
    try:
        epss = float(raw.get('epss') or raw.get('epss_score') or 0)
    except (ValueError, TypeError):
        pass
    return {
        'cve_id': cve_id,
        'summary': raw.get('description') or raw.get('summary') or '',
        'severity': SEVERITY_MAP.get(severity_raw, 'info'),
        'severity_raw': severity_raw,
        'cvss': cvss,
        'epss': epss,
        'is_kev': is_kev,
        'has_poc': has_poc,
        'references': raw.get('references') or [],
        'published': raw.get('published') or raw.get('publish_date') or '',
        'raw': raw,
    }


def search_tech_cves(
    tech_name: str,
    version: str = '',
    severity: str = 'medium,high,critical',
    limit: int = MAX_RESULTS_PER_QUERY,
) -> list[dict]:
    """
    Search vulnx for CVEs affecting a detected technology.

    Args:
        tech_name: library or framework name (e.g. "openssl", "log4j", "okhttp")
        version:   optional version string to narrow results
        severity:  comma-separated severity filter
        limit:     max results to return

    Returns:
        list of normalized finding dicts, sorted by CVSS desc
    """
    query = tech_name
    if version:
        query = f'{tech_name} {version}'
    args = [
        'search',
        '--query', query,
        '--severity', severity,
        '--limit', str(limit),
    ]
    items = _run_vulnx(args)
    if items is None:
        return []
    findings = [_parse_vuln(item) for item in items if isinstance(item, dict)]
    findings.sort(key=lambda f: (f['is_kev'], f['has_poc'], f['cvss']), reverse=True)
    return findings


def get_cve_detail(cve_id: str) -> dict | None:
    """
    Fetch full details for a specific CVE ID via vulnx.
    Returns None if not found or vulnx unavailable.
    """
    items = _run_vulnx(['id', cve_id])
    if not items:
        return None
    return _parse_vuln(items[0]) if items else None


def analyze_tech_stack(
    tech_stack: list[dict],
    severity_filter: str = 'medium,high,critical',
) -> dict[str, Any]:
    """
    Run vulnx CVE lookup for each technology in an app's detected stack.

    Args:
        tech_stack: list of dicts with at minimum {"name": str}.
                    May include {"version": str} for narrower matches.
        severity_filter: comma-separated severity filter passed to vulnx

    Returns:
        {
            "findings": [<finding dicts with added "tech" key>],
            "summary": {
                "technologies_checked": int,
                "technologies_with_cves": int,
                "kev_count": int,
                "poc_count": int,
                "critical_high_count": int,
                "total_cves": int,
            },
            "vulnx_available": bool,
        }
    """
    if not _vulnx_available():
        return {
            'findings': [],
            'summary': {
                'technologies_checked': 0,
                'technologies_with_cves': 0,
                'kev_count': 0,
                'poc_count': 0,
                'critical_high_count': 0,
                'total_cves': 0,
            },
            'vulnx_available': False,
        }

    all_findings = []
    techs_with_cves = set()

    for tech in tech_stack:
        name = tech.get('name') or tech.get('library') or ''
        version = tech.get('version') or tech.get('ver') or ''
        if not name:
            continue
        results = search_tech_cves(name, version=version, severity=severity_filter)
        for finding in results:
            finding['tech'] = name
            finding['tech_version'] = version
            all_findings.append(finding)
            techs_with_cves.add(name)

    kev_count = sum(1 for f in all_findings if f['is_kev'])
    poc_count = sum(1 for f in all_findings if f['has_poc'])
    crit_high = sum(1 for f in all_findings if f['severity'] == 'high')

    return {
        'findings': all_findings,
        'summary': {
            'technologies_checked': len(tech_stack),
            'technologies_with_cves': len(techs_with_cves),
            'kev_count': kev_count,
            'poc_count': poc_count,
            'critical_high_count': crit_high,
            'total_cves': len(all_findings),
        },
        'vulnx_available': True,
    }
