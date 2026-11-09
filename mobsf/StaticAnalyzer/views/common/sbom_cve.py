#!/usr/bin/python
# coding=utf-8
"""
SBOM CVE correlation using the OSV.dev API.

Queries https://api.osv.dev/v1/querybatch for each versioned dependency
in the MobSF SBOM and returns enriched results with CVE IDs, severity,
and CVSS scores from the NVD database.

OSV API docs: https://google.github.io/osv.dev/api/
"""
import json as _json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_BATCH_SIZE = 50
REQUEST_TIMEOUT = 30
RETRY_DELAY = 2
MAX_RETRIES = 3

SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}


def _osv_query_batch(packages: list[dict]) -> list[dict]:
    """
    POST to OSV /v1/querybatch.
    packages: list of {"package": {"name": str, "ecosystem": str}, "version": str}
    Returns list of {"vulns": [...]} parallel to input, or empty on failure.
    """
    try:
        payload = _json.dumps({"queries": packages}).encode()
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for attempt in range(MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    return _json.loads(resp.read()).get("results", [])
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.warning("OSV API HTTP %s: %s", e.code, e.reason)
                return []
            except Exception as e:
                logger.warning("OSV API request failed: %s", e)
                return []
    except Exception as e:
        logger.warning("OSV batch query error: %s", e)
    return []


def _extract_severity(vuln: dict) -> tuple[str, float]:
    """Return (severity_label, cvss_score) for the highest-severity rating."""
    best_label = 'NONE'
    best_score = 0.0
    for sev in vuln.get('severity', []):
        label = sev.get('type', 'NONE').upper()
        score = 0.0
        # CVSS v3 vector string does not embed the base score; read from database_specific
        try:
            db_cvss = vuln.get('database_specific', {}).get('cvss', {})
            if isinstance(db_cvss, dict):
                score = float(db_cvss.get('score', 0) or 0)
            elif isinstance(db_cvss, (int, float)):
                score = float(db_cvss)
        except (ValueError, TypeError):
            score = 0.0
        # Fall back to approximate ranges from severity label when score is absent
        if score == 0.0:
            score = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.5, 'LOW': 2.5}.get(label, 0.0)
        if SEVERITY_ORDER.get(label, 0) > SEVERITY_ORDER.get(best_label, 0):
            best_label = label
        if score > best_score:
            best_score = score
    return best_label, best_score


def _build_finding(dep_name: str, dep_version: str, vuln: dict) -> dict:
    """Convert an OSV vulnerability into a MobSF-style finding dict."""
    aliases = vuln.get('aliases', [])
    cve_ids = [a for a in aliases if a.startswith('CVE-')]
    severity_label, cvss_score = _extract_severity(vuln)
    if cvss_score >= 7.0:
        mobsf_severity = 'high'
    elif cvss_score >= 4.0:
        mobsf_severity = 'warning'
    else:
        mobsf_severity = 'info'
    refs = [r.get('url', '') for r in vuln.get('references', []) if r.get('url')][:3]
    summary = vuln.get('summary', '') or vuln.get('details', '')[:200]
    return {
        'library': dep_name,
        'version': dep_version,
        'osv_id': vuln.get('id', ''),
        'cve_ids': cve_ids,
        'summary': summary,
        'severity': mobsf_severity,
        'cvss_score': cvss_score,
        'severity_label': severity_label,
        'references': refs,
        'fixed_in': _get_fixed_version(vuln),
    }


def _get_fixed_version(vuln: dict) -> str:
    """Extract the first fixed version from affected ranges."""
    try:
        for affected in vuln.get('affected', []):
            for r in affected.get('ranges', []):
                for event in r.get('events', []):
                    if 'fixed' in event:
                        return str(event['fixed'])
    except Exception:
        pass
    return ''


def _detect_ecosystem(pkg_name: str, ecosystem_hint: str = '') -> str:
    """Guess OSV ecosystem from package name patterns."""
    if ecosystem_hint:
        return ecosystem_hint
    name_lower = pkg_name.lower()
    if ':' in pkg_name or name_lower.startswith(('com.', 'org.', 'io.', 'net.', 'androidx.')):
        return 'Maven'
    if name_lower.startswith('@'):
        return 'npm'
    if name_lower.endswith('-ios') or name_lower.endswith('kit'):
        return 'CocoaPods'
    return 'Maven'


def correlate_sbom_cves(
    sbom_entries: list[dict],
    ecosystem_hint: str = '',
    max_results: int = 500,
) -> dict[str, Any]:
    """
    Correlate SBOM entries against OSV.dev for known CVEs.

    Args:
        sbom_entries: list of dicts with at minimum {"name": str, "version": str}.
                      May also include {"ecosystem": str} for precision.
        ecosystem_hint: override ecosystem for all entries (e.g. "Maven", "npm")
        max_results: cap total findings returned

    Returns:
        {
            "findings": [<finding dicts sorted by CVSS desc>],
            "summary": {
                "total_deps": int,
                "deps_with_cves": int,
                "critical_count": int,
                "high_count": int,
                "medium_count": int,
                "low_count": int,
                "total_cves": int,
            },
            "scanned": int,
            "skipped": int,
        }
    """
    findings = []
    skipped = 0
    versioned = []
    for entry in sbom_entries:
        name = entry.get('name') or entry.get('package') or ''
        version = entry.get('version') or entry.get('ver') or ''
        if not name or not version or version in ('unknown', 'latest', ''):
            skipped += 1
            continue
        eco = entry.get('ecosystem') or ecosystem_hint or _detect_ecosystem(name)
        versioned.append((name, version, eco))

    deps_with_cves: set[str] = set()
    total_cves = 0
    for i in range(0, len(versioned), OSV_BATCH_SIZE):
        chunk = versioned[i:i + OSV_BATCH_SIZE]
        queries = [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for name, ver, eco in chunk
        ]
        results = _osv_query_batch(queries)
        for (name, ver, _eco), result in zip(chunk, results):
            for vuln in result.get('vulns', []):
                findings.append(_build_finding(name, ver, vuln))
                deps_with_cves.add(name)
                total_cves += 1
                if total_cves >= max_results:
                    break
            if total_cves >= max_results:
                break
        if total_cves >= max_results:
            break

    findings.sort(key=lambda f: f['cvss_score'], reverse=True)

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        label = f.get('severity_label', 'NONE').upper()
        if label in sev_counts:
            sev_counts[label] += 1

    return {
        'findings': findings,
        'summary': {
            'total_deps': len(versioned),
            'deps_with_cves': len(deps_with_cves),
            'critical_count': sev_counts['CRITICAL'],
            'high_count': sev_counts['HIGH'],
            'medium_count': sev_counts['MEDIUM'],
            'low_count': sev_counts['LOW'],
            'total_cves': total_cves,
        },
        'scanned': len(versioned),
        'skipped': skipped,
    }
