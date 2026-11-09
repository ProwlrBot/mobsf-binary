#!/usr/bin/python
# coding=utf-8
"""
MobSF MCP Server — exposes MobSF's REST API as MCP tools so that
Claude Code, REA, and other MCP clients can drive scans programmatically.

Usage:
    python -m mobsf.MCP.server                 # default stdio transport
    MOBSF_URL=http://localhost:8000 python -m mobsf.MCP.server

Environment variables:
    MOBSF_URL       MobSF base URL (default: http://localhost:8000)
    MOBSF_API_KEY   MobSF REST API key (required)
"""
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    sys.exit('httpx is required: pip install httpx')

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types as mcp_types
except ImportError:
    sys.exit('mcp is required: pip install mcp')

logger = logging.getLogger(__name__)

MOBSF_URL = os.environ.get('MOBSF_URL', 'http://localhost:8000').rstrip('/')
MOBSF_KEY = os.environ.get('MOBSF_API_KEY', '')

server = Server('mobsf-binary')

TOOLS: list[mcp_types.Tool] = [
    mcp_types.Tool(
        name='mobsf_upload',
        description=(
            'Upload an APK, IPA, ZIP, EXE, DLL, or other supported file to MobSF '
            'for analysis. Returns the scan hash used in subsequent calls.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'file_path': {
                    'type': 'string',
                    'description': 'Absolute path to the file on disk.',
                },
            },
            'required': ['file_path'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_scan',
        description='Trigger static analysis on a previously uploaded file.',
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {
                    'type': 'string',
                    'description': 'MD5 hash returned by mobsf_upload.',
                },
                'scan_type': {
                    'type': 'string',
                    'description': (
                        'File type: apk, ipa, zip, jar, aar, appx, so, '
                        'dylib, a, ar, exe, or dll.'
                    ),
                },
                'file_name': {
                    'type': 'string',
                    'description': 'Original file name including extension.',
                },
            },
            'required': ['hash', 'scan_type', 'file_name'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_report',
        description='Retrieve the full JSON analysis report for a completed scan.',
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {'type': 'string'},
                'scan_type': {'type': 'string'},
            },
            'required': ['hash', 'scan_type'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_scorecard',
        description='Get the security scorecard (CVSS-equivalent ratings) for a scan.',
        inputSchema={
            'type': 'object',
            'properties': {'hash': {'type': 'string'}},
            'required': ['hash'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_source',
        description='Read a decompiled source file from a scan by its relative path.',
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {'type': 'string'},
                'file': {
                    'type': 'string',
                    'description': 'Relative path within the decompiled output tree.',
                },
                'type': {
                    'type': 'string',
                    'description': 'Scan type: apk or ipa.',
                },
            },
            'required': ['hash', 'file', 'type'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_binary_info',
        description=(
            'Get checksec results and symbol info for all native libraries '
            '(.so, .dylib, .dll, .exe) found in a scan.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {'type': 'string'},
                'scan_type': {
                    'type': 'string',
                    'description': 'Scan type: apk, ipa, zip, appx, exe, dll (default: apk)',
                },
            },
            'required': ['hash'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_sbom',
        description='Get the Software Bill of Materials (SBOM / dependency list) for a scan.',
        inputSchema={
            'type': 'object',
            'properties': {'hash': {'type': 'string'}},
            'required': ['hash'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_recent_scans',
        description='List the most recent MobSF scans with their hashes and metadata.',
        inputSchema={
            'type': 'object',
            'properties': {
                'page': {'type': 'integer', 'default': 1},
                'page_size': {'type': 'integer', 'default': 10},
            },
        },
    ),
    mcp_types.Tool(
        name='mobsf_compare',
        description=(
            'Compare two scans of the same app across versions. '
            'Surfaces added/removed permissions, new dangerous APIs, and '
            'security regression between builds.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'hash1': {
                    'type': 'string',
                    'description': 'MD5 of the first (older) scan.',
                },
                'hash2': {
                    'type': 'string',
                    'description': 'MD5 of the second (newer) scan.',
                },
            },
            'required': ['hash1', 'hash2'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_delete_scan',
        description='Delete a scan and all its associated data from MobSF.',
        inputSchema={
            'type': 'object',
            'properties': {'hash': {'type': 'string'}},
            'required': ['hash'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_jwt_scan',
        description=(
            'Scan a list of strings for embedded JWT tokens and audit them '
            'for alg:none, RS256→HS256 confusion, missing expiry, and sensitive payload fields.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'strings': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'Strings extracted from an APK/IPA binary or source.',
                },
            },
            'required': ['strings'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_signing_check',
        description=(
            'Score an APK signing configuration. Detects Janus (CVE-2017-13156) on '
            'V1-only signed APKs and reports V2/V3/V4 scheme presence.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'signing_info': {
                    'type': 'object',
                    'description': 'Signing info dict from MobSF cert analysis output.',
                },
            },
            'required': ['signing_info'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_cve_lookup',
        description=(
            'Look up CVEs for versioned SBOM dependencies via OSV.dev. '
            'Returns CVE IDs, CVSS scores, severity, and fixed versions.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'entries': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'name': {'type': 'string'},
                            'version': {'type': 'string'},
                            'ecosystem': {'type': 'string'},
                        },
                        'required': ['name', 'version'],
                    },
                    'description': 'List of {name, version} dependency entries.',
                },
                'ecosystem': {
                    'type': 'string',
                    'description': 'Default OSV ecosystem (e.g. Maven, npm, PyPI)',
                },
            },
            'required': ['entries'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_get_native_paths',
        description=(
            'Get filesystem paths of native libraries (.so, .dylib, .dll, .exe) '
            'extracted from a MobSF scan. Pass these paths to REA open_binary() for '
            'deep analysis with Ghidra, Binary Ninja, r2, or other RE backends.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {
                    'type': 'string',
                    'description': 'MD5 scan hash from mobsf_upload.',
                },
                'extensions': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'Filter by extension (e.g. [".so", ".dll"]). Default: all native.',
                },
            },
            'required': ['hash'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_vulnx_lookup',
        description=(
            'Search ProjectDiscovery vulnx (vulnerability.sh) for CVEs affecting '
            'a detected technology. Returns CVE IDs, CVSS scores, EPSS scores, '
            'CISA-KEV flag, and PoC availability — sorted by triage priority. '
            'Requires vulnx CLI installed and authenticated.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'tech_name': {
                    'type': 'string',
                    'description': 'Library or framework name (e.g. "openssl", "okhttp", "log4j")',
                },
                'version': {
                    'type': 'string',
                    'description': 'Optional version string to narrow results',
                },
                'severity': {
                    'type': 'string',
                    'description': 'Comma-separated severity filter (default: medium,high,critical)',
                },
            },
            'required': ['tech_name'],
        },
    ),
    mcp_types.Tool(
        name='mobsf_masvs_coverage',
        description=(
            'Get MASVS v2.1 coverage report for the scanner. Shows which of the 27 controls '
            'are fully covered, partially covered, or gaps. Optionally tags a list of findings '
            'with MASVS control IDs so the triage UI can display MASVS badges.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'findings': {
                    'type': 'array',
                    'description': 'Optional findings list to tag with MASVS control IDs.',
                },
            },
        },
    ),
    mcp_types.Tool(
        name='mobsf_triage',
        description=(
            'Run the full triage pipeline on a MobSF scan: '
            'FP filter → LLM scoring → MASVS tagging → HTML report. '
            'Returns bounty_score, priority (P1/P2/P3/noise), next decisive test, '
            'MASVS control IDs, and analyst-ready HTML report with proven/disproven controls.'
        ),
        inputSchema={
            'type': 'object',
            'properties': {
                'hash': {
                    'type': 'string',
                    'description': 'MD5 scan hash from mobsf_upload.',
                },
                'skip_llm': {
                    'type': 'boolean',
                    'description': 'Force rule-based scoring (no LLM API call)',
                    'default': False,
                },
                'skip_noise_in_report': {
                    'type': 'boolean',
                    'description': 'Omit noise findings from HTML report',
                    'default': False,
                },
            },
            'required': ['hash'],
        },
    ),
]


def _headers() -> dict:
    return {
        'Authorization': MOBSF_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
    }


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.get(
            f'{MOBSF_URL}{path}', headers=_headers(), params=params)
        r.raise_for_status()
        return r.json()


async def _post(path: str, data: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f'{MOBSF_URL}{path}', headers=_headers(), data=data)
        r.raise_for_status()
        return r.json()


async def _upload(file_path: str) -> Any:
    path = Path(file_path)
    async with httpx.AsyncClient(timeout=300) as client:
        with open(path, 'rb') as f:
            r = await client.post(
                f'{MOBSF_URL}/api/v1/upload',
                headers={'Authorization': MOBSF_KEY},
                files={'file': (path.name, f, 'application/octet-stream')},
            )
        r.raise_for_status()
        return r.json()


def _text(data: Any) -> list[mcp_types.TextContent]:
    return [mcp_types.TextContent(type='text', text=json.dumps(data, indent=2))]


@server.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[mcp_types.TextContent]:
    try:
        if name == 'mobsf_upload':
            result = await _upload(arguments['file_path'])

        elif name == 'mobsf_scan':
            result = await _post('/api/v1/scan', {
                'hash': arguments['hash'],
                'scan_type': arguments['scan_type'],
                'file_name': arguments['file_name'],
                're_scan': arguments.get('re_scan', 0),
            })

        elif name == 'mobsf_report':
            result = await _post('/api/v1/report_json', {
                'hash': arguments['hash'],
                'scan_type': arguments['scan_type'],
            })

        elif name == 'mobsf_scorecard':
            result = await _post('/api/v1/scorecard', {
                'hash': arguments['hash'],
            })

        elif name == 'mobsf_source':
            result = await _post('/api/v1/view_source', {
                'hash': arguments['hash'],
                'file': arguments['file'],
                'type': arguments['type'],
            })

        elif name == 'mobsf_binary_info':
            # Pull the full report and extract only the binary analysis sections
            scan_type = arguments.get('scan_type', 'apk')
            report = await _post('/api/v1/report_json', {
                'hash': arguments['hash'],
                'scan_type': scan_type,
            })
            result = {
                'binary_analysis': report.get('binary_analysis', {}),
                'elf_analysis': report.get('elf_analysis', {}),
                'pe_analysis': report.get('pe_analysis', {}),
            }

        elif name == 'mobsf_sbom':
            result = await _get(f'/api/v1/scan_library/{arguments["hash"]}')

        elif name == 'mobsf_recent_scans':
            page = arguments.get('page', 1)
            size = arguments.get('page_size', 10)
            result = await _get(f'/api/v1/scans/{size}/{page}')

        elif name == 'mobsf_compare':
            result = await _get(
                f'/api/v1/compare/{arguments["hash1"]}/{arguments["hash2"]}')

        elif name == 'mobsf_delete_scan':
            result = await _post('/api/v1/delete_scan', {
                'hash': arguments['hash'],
            })

        elif name == 'mobsf_jwt_scan':
            from mobsf.StaticAnalyzer.views.common.jwt_analysis import analyze_jwts
            result = analyze_jwts(arguments.get('strings', []))

        elif name == 'mobsf_signing_check':
            from mobsf.StaticAnalyzer.views.android.cert_analysis import score_signing_security
            result = score_signing_security(arguments.get('signing_info', {}))

        elif name == 'mobsf_cve_lookup':
            from mobsf.StaticAnalyzer.views.common.sbom_cve import correlate_sbom_cves
            result = correlate_sbom_cves(
                arguments.get('entries', []),
                ecosystem_hint=arguments.get('ecosystem', ''),
            )

        elif name == 'mobsf_get_native_paths':
            from django.conf import settings
            from mobsf.StaticAnalyzer.views.common.evidence_path import validate_scan_hash
            try:
                scan_hash = validate_scan_hash(arguments.get('hash', ''))
            except ValueError as _e:
                result = {'error': str(_e)}
                return [TextContent(type='text', text=json.dumps(result, indent=2))]
            exts = set(arguments.get('extensions') or ['.so', '.dylib', '.dll', '.exe', '.a'])
            scan_dir = Path(settings.UPLD_DIR) / scan_hash
            if not scan_dir.exists():
                result = {'error': f'Scan directory not found: {scan_hash}'}
            else:
                paths = [
                    str(p) for p in scan_dir.rglob('*')
                    if p.suffix.lower() in exts and p.is_file()
                ]
                result = {
                    'scan_dir': str(scan_dir),
                    'native_libs': sorted(paths),
                    'count': len(paths),
                    'hint': (
                        'Pass each path to REA open_binary() for deep analysis. '
                        'REA wraps Ghidra, Binary Ninja, r2, frida, and other RE backends.'
                    ),
                }

        elif name == 'mobsf_vulnx_lookup':
            from mobsf.StaticAnalyzer.views.common.vulnx_bridge import (
                search_tech_cves,
                _vulnx_available,
            )
            if not _vulnx_available():
                result = {
                    'error': 'vulnx not available',
                    'hint': 'Install from https://docs.projectdiscovery.io/tools/vulnx',
                }
            else:
                result = search_tech_cves(
                    tech_name=arguments['tech_name'],
                    version=arguments.get('version', ''),
                    severity=arguments.get('severity', 'medium,high,critical'),
                )

        elif name == 'mobsf_masvs_coverage':
            from mobsf.StaticAnalyzer.views.common.masvs_coverage import (
                coverage_report,
                tag_findings_with_masvs,
            )
            findings = list(arguments.get('findings') or [])
            if findings:
                findings = tag_findings_with_masvs(findings)
            result = coverage_report(findings or None)

        elif name == 'mobsf_triage':
            # Fetch findings from MobSF report, then run triage pipeline
            try:
                report = await _post('/api/v1/report_json', {
                    'hash': arguments['hash'],
                    'scan_type': 'apk',
                })
            except Exception:
                report = {}
            # Flatten code_analysis into findings list
            findings = []
            code_analysis = report.get('code_analysis', {})
            if isinstance(code_analysis, dict):
                for rule_id, item in code_analysis.items():
                    if isinstance(item, dict):
                        meta = item.get('metadata', {})
                        findings.append({
                            'title': meta.get('description', rule_id),
                            'description': meta.get('description', ''),
                            'rule_id': rule_id,
                            'severity': meta.get('severity', 'info'),
                            'file_path': '',
                            'code': '',
                        })
            app_info = {
                'app_name': report.get('app_name', ''),
                'package': report.get('package_name', ''),
                'version': report.get('version_name', ''),
                'platform': 'android',
            }
            from mobsf.StaticAnalyzer.views.common.triage_pipeline import run_triage
            triage_result = run_triage(
                findings,
                app_info=app_info,
                skip_llm=arguments.get('skip_llm', False),
                skip_noise_in_report=arguments.get('skip_noise_in_report', False),
            )
            result = {
                'stats': triage_result['stats'],
                'coverage_summary': triage_result.get('coverage', {}).get('summary', {}),
                'gap_controls': triage_result.get('coverage', {}).get('gap_controls', []),
                'llm_provider': triage_result['llm_status'].get('provider', 'none'),
                'top_findings': [
                    {
                        'title': f.get('title', ''),
                        'priority': f.get('triage', {}).get('priority', 'noise'),
                        'bounty_score': f.get('triage', {}).get('bounty_score', 0),
                        'fp_risk': f.get('triage', {}).get('fp_risk', 'high'),
                        'masvs_ids': f.get('masvs_ids', []),
                        'next_action': f.get('triage', {}).get('next_action', ''),
                        'reasoning': f.get('triage', {}).get('reasoning', ''),
                    }
                    for f in triage_result['findings'][:20]
                ],
                'html_bytes': len(triage_result.get('html', '')),
                'hint': 'Call /api/v1/triage with this hash to get the full HTML report',
            }

        else:
            result = {'error': f'Unknown tool: {name}'}

    except httpx.HTTPStatusError as e:
        result = {
            'error': f'HTTP {e.response.status_code}',
            'detail': e.response.text[:500],
        }
    except Exception as e:
        result = {'error': str(e)}

    return _text(result)


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            server.create_initialization_options())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
