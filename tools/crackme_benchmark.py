#!/usr/bin/python
# coding=utf-8
"""
OWASP MAS CrackMe benchmark runner.

Downloads official OWASP UnCrackable Android APKs and runs MobSF's
static analysis pipeline against each, then validates that the scanner
found the expected findings for each control.

Usage:
    python3 tools/crackme_benchmark.py --list
    python3 tools/crackme_benchmark.py [--mobsf-url http://localhost:8000] [--api-key KEY]
    python3 tools/crackme_benchmark.py --offline   # use cached APKs only
    python3 tools/crackme_benchmark.py --json

The CrackMe apps are canonical test cases for MASVS controls.
  MISS a known finding  → coverage gap
  SPURIOUS fire         → FP calibration issue
"""
import argparse
import json
import logging
import os
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

CRACKME_REGISTRY = [
    {
        'id': 'android-uncrackable-l1',
        'name': 'UnCrackable App for Android Level 1',
        'url': 'https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk',
        'package': 'owasp.mstg.uncrackable1',
        'masvs_targets': ['RESILIENCE-1', 'RESILIENCE-3', 'CRYPTO-1'],
        'expected_findings': [
            {
                'masvs_id': 'RESILIENCE-1',
                'description': 'Root detection present',
                'pattern': r'isRooted|RootDetection|su.*binary',
                'verdict': 'present',
            },
            {
                'masvs_id': 'RESILIENCE-3',
                'description': 'String obfuscation / encoding present',
                'pattern': r'Base64|encrypt|cipher',
                'verdict': 'present',
            },
        ],
    },
    {
        'id': 'android-uncrackable-l2',
        'name': 'UnCrackable App for Android Level 2',
        'url': 'https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_02/UnCrackable-Level2.apk',
        'package': 'owasp.mstg.uncrackable2',
        'masvs_targets': ['RESILIENCE-1', 'RESILIENCE-4', 'CODE-3'],
        'expected_findings': [
            {
                'masvs_id': 'RESILIENCE-1',
                'description': 'Root detection + tamper check',
                'pattern': r'isRooted|tamper|integrity',
                'verdict': 'present',
            },
            {
                'masvs_id': 'CODE-3',
                'description': 'Debug detection present',
                'pattern': r'isDebuggerConnected|anti.?debug',
                'verdict': 'present',
            },
        ],
    },
    {
        'id': 'android-uncrackable-l3',
        'name': 'UnCrackable App for Android Level 3',
        'url': 'https://github.com/OWASP/owasp-mstg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk',
        'package': 'owasp.mstg.uncrackable3',
        'masvs_targets': ['RESILIENCE-1', 'RESILIENCE-2', 'RESILIENCE-4'],
        'expected_findings': [
            {
                'masvs_id': 'RESILIENCE-4',
                'description': 'Anti-debug and Frida detection',
                'pattern': r'frida|anti.?debug|ptrace|isDebuggerConnected',
                'verdict': 'present',
            },
            {
                'masvs_id': 'RESILIENCE-2',
                'description': 'Signature/integrity check',
                'pattern': r'signature|digest|hash.*apk',
                'verdict': 'present',
            },
        ],
    },
]


@dataclass
class BenchmarkResult:
    crackme_id: str
    crackme_name: str
    status: str = 'pending'
    findings_count: int = 0
    expected_checks: list[dict] = field(default_factory=list)
    check_results: list[dict] = field(default_factory=list)
    scan_hash: str = ''
    error: str = ''
    duration_s: float = 0.0


def _download_apk(url: str, dest: Path) -> bool:
    try:
        logger.info('Downloading %s', url)
        req = urllib.request.Request(url, headers={'User-Agent': 'MobSF-Benchmark/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as e:
        logger.error('Download failed: %s', e)
        return False


def _mobsf_upload(apk_path: Path, mobsf_url: str, api_key: str) -> str | None:
    try:
        import httpx
        with open(apk_path, 'rb') as f:
            r = httpx.post(
                f'{mobsf_url}/api/v1/upload',
                headers={'Authorization': api_key},
                files={'file': (apk_path.name, f, 'application/octet-stream')},
                timeout=120,
            )
            r.raise_for_status()
            return r.json().get('hash')
    except Exception as e:
        logger.error('Upload failed: %s', e)
        return None


def _mobsf_scan_wait(scan_hash: str, mobsf_url: str, api_key: str, timeout: int = 300) -> dict | None:
    try:
        import httpx
        hdrs = {'Authorization': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
        client = httpx.Client(timeout=120)
        client.post(
            f'{mobsf_url}/api/v1/scan', headers=hdrs,
            data={'hash': scan_hash, 'scan_type': 'apk', 'file_name': f'{scan_hash}.apk'},
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            r = client.post(
                f'{mobsf_url}/api/v1/report_json', headers=hdrs,
                data={'hash': scan_hash, 'scan_type': 'apk'},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('md5') == scan_hash:
                    return data
        return None
    except Exception as e:
        logger.error('Scan failed: %s', e)
        return None


def _check_finding(report: dict, pattern: str) -> bool:
    import re
    pat = re.compile(pattern, re.IGNORECASE)
    for section in [
        json.dumps(report.get('code_analysis', {})),
        json.dumps(report.get('permissions', {})),
        json.dumps(report.get('manifest_analysis', {})),
        json.dumps(report.get('binary_analysis', {})),
        json.dumps(report.get('strings', [])),
    ]:
        if pat.search(section):
            return True
    return False


def run_benchmark(
    crackmes: list[dict] | None = None,
    mobsf_url: str = 'http://localhost:8000',
    api_key: str = '',
    download_dir: Path | None = None,
    offline: bool = False,
) -> list[BenchmarkResult]:
    """Run the OWASP MAS CrackMe benchmark suite against a MobSF instance."""
    if crackmes is None:
        crackmes = CRACKME_REGISTRY
    if download_dir is None:
        download_dir = Path.home() / '.cache' / 'mobsf-crackmes'
    download_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for crackme in crackmes:
        result = BenchmarkResult(
            crackme_id=crackme['id'],
            crackme_name=crackme['name'],
            expected_checks=crackme['expected_findings'],
        )
        t0 = time.time()
        try:
            apk_path = download_dir / f"{crackme['id']}.apk"
            if not apk_path.exists():
                if offline:
                    result.status = 'skipped'
                    result.error = 'APK not cached and offline=True'
                    results.append(result)
                    continue
                if not _download_apk(crackme['url'], apk_path):
                    result.status = 'error'
                    result.error = 'Download failed'
                    results.append(result)
                    continue

            if not api_key:
                result.status = 'skipped'
                result.error = 'No MobSF API key — set MOBSF_API_KEY or pass --api-key'
                result.duration_s = time.time() - t0
                results.append(result)
                continue

            scan_hash = _mobsf_upload(apk_path, mobsf_url, api_key)
            if not scan_hash:
                result.status = 'error'
                result.error = 'Upload failed'
                results.append(result)
                continue
            result.scan_hash = scan_hash

            report = _mobsf_scan_wait(scan_hash, mobsf_url, api_key)
            if not report:
                result.status = 'error'
                result.error = 'Scan timed out'
                results.append(result)
                continue

            all_pass = True
            for check in crackme['expected_findings']:
                found = _check_finding(report, check['pattern'])
                expected_present = check['verdict'] == 'present'
                passed = found == expected_present
                if not passed:
                    all_pass = False
                result.check_results.append({
                    'masvs_id': check['masvs_id'],
                    'description': check['description'],
                    'expected': check['verdict'],
                    'found': found,
                    'passed': passed,
                })
            result.status = 'passed' if all_pass else 'failed'

        except Exception as e:
            result.status = 'error'
            result.error = str(e)

        result.duration_s = time.time() - t0
        results.append(result)

    return results


def _print_report(results: list[BenchmarkResult]) -> None:
    passed = sum(1 for r in results if r.status == 'passed')
    total = len(results)
    print(f'\nOWASP MAS CrackMe Benchmark: {passed}/{total} passed\n')
    for r in results:
        icon = {'passed': '✓', 'failed': '✗', 'error': '!', 'skipped': '~'}.get(r.status, '?')
        print(f'  {icon} [{r.status.upper():7s}] {r.crackme_name}  ({r.duration_s:.1f}s)')
        for chk in r.check_results:
            chk_icon = '  ✓' if chk['passed'] else '  ✗'
            print(f'      {chk_icon} {chk["masvs_id"]}: {chk["description"]}')
        if r.error:
            print(f'           → {r.error}')
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description='OWASP MAS CrackMe Benchmark Runner')
    parser.add_argument('--mobsf-url', default=os.environ.get('MOBSF_URL', 'http://localhost:8000'))
    parser.add_argument('--api-key',   default=os.environ.get('MOBSF_API_KEY', ''))
    parser.add_argument('--list',    action='store_true', help='List benchmarks and exit')
    parser.add_argument('--offline', action='store_true', help='Use cached APKs only, no downloads')
    parser.add_argument('--json',    action='store_true', help='Output JSON')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')

    if args.list:
        for c in CRACKME_REGISTRY:
            print(f"{c['id']:35s}  {c['name']}")
            for t in c['masvs_targets']:
                print(f'  → {t}')
        return

    results = run_benchmark(
        mobsf_url=args.mobsf_url,
        api_key=args.api_key,
        offline=args.offline,
    )

    if args.json:
        import dataclasses
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    else:
        _print_report(results)


if __name__ == '__main__':
    main()
