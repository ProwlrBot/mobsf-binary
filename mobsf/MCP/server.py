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
            'properties': {'hash': {'type': 'string'}},
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
