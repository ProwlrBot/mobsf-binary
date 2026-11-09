# -*- coding: utf_8 -*-
"""Binary Intelligence — standalone EXE/DLL/ELF/SO/MachO scanner."""
import hashlib
import logging
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from mobsf.MobSF.views.authorization import has_permission, Permissions

logger = logging.getLogger(__name__)

ALLOWED_EXTS = {
    '.exe': 'pe',
    '.dll': 'pe',
    '.sys': 'pe',
    '.scr': 'pe',
    '.ocx': 'pe',
    '.so':  'elf',
    '.elf': 'elf',
    '.out': 'elf',
}

MAX_BINARY_SIZE = 200 * 1024 * 1024  # 200 MB


@login_required
def binary_intel_home(request):
    """Render the Binary Intelligence upload page."""
    return render(request, 'static_analysis/binary_intel.html', {
        'allowed_exts': sorted(ALLOWED_EXTS.keys()),
    })


@login_required
@require_POST
def binary_intel_scan(request, api=False):
    """Accept a binary upload, run checksec, return results page."""
    try:
        if not has_permission(request, Permissions.SCAN, api):
            return render(request, 'static_analysis/binary_intel.html', {
                'error': 'Permission Denied',
                'allowed_exts': sorted(ALLOWED_EXTS.keys()),
            })

        uploaded = request.FILES.get('binary')
        if not uploaded:
            return render(request, 'static_analysis/binary_intel.html', {
                'error': 'No file provided.',
                'allowed_exts': sorted(ALLOWED_EXTS.keys()),
            })

        filename = uploaded.name
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTS:
            return render(request, 'static_analysis/binary_intel.html', {
                'error': f'Unsupported file type: {ext}. Accepted: {", ".join(sorted(ALLOWED_EXTS))}',
                'allowed_exts': sorted(ALLOWED_EXTS.keys()),
            })

        if uploaded.size > MAX_BINARY_SIZE:
            return render(request, 'static_analysis/binary_intel.html', {
                'error': f'File too large ({uploaded.size // 1048576} MB). Max 200 MB.',
                'allowed_exts': sorted(ALLOWED_EXTS.keys()),
            })

        # Save to temp location under UPLD_DIR
        raw = uploaded.read()
        md5 = hashlib.md5(raw).hexdigest()
        scan_dir = Path(settings.UPLD_DIR) / f'binaryintel_{md5}'
        scan_dir.mkdir(parents=True, exist_ok=True)
        binary_path = scan_dir / filename
        binary_path.write_bytes(raw)

        arch = ALLOWED_EXTS[ext]
        result = _run_checksec(binary_path, arch, md5)
        result['filename'] = filename
        result['filesize_kb'] = round(len(raw) / 1024, 1)
        result['md5'] = md5
        result['arch'] = arch.upper()

        return render(request, 'static_analysis/binary_intel.html', {
            'allowed_exts': sorted(ALLOWED_EXTS.keys()),
            'result': result,
        })

    except Exception as exc:
        logger.exception('Binary Intel scan error')
        return render(request, 'static_analysis/binary_intel.html', {
            'error': f'Scan failed: {exc}',
            'allowed_exts': sorted(ALLOWED_EXTS.keys()),
        })


def _run_checksec(path: Path, arch: str, checksum: str) -> dict:
    """Run the appropriate checksec and return a unified dict."""
    result = {'checksec': {}, 'strings_sample': [], 'symbols': [], 'extra': {}}
    try:
        if arch == 'pe':
            from mobsf.StaticAnalyzer.views.common.binary.pe import PEChecksec
            chk = PEChecksec(path, path.name)
            result['checksec'] = chk.checksec() or {}
            result['strings_sample'] = (chk.strings() or [])[:50]
            result['symbols'] = (chk.get_symbols() or [])[:100]
        elif arch == 'elf':
            from mobsf.StaticAnalyzer.views.common.binary.elf import ELFChecksec
            chk = ELFChecksec(path, path.name)
            result['checksec'] = chk.checksec() or {}
            result['strings_sample'] = (chk.strings() or [])[:50]
            result['symbols'] = (chk.get_symbols() or [])[:100]
            # RPATH check via tools_bridge
            try:
                from mobsf.StaticAnalyzer.views.common.binary.tools_bridge import readelf_dynamic
                dyn = readelf_dynamic(str(path))
                if dyn.get('rpath'):
                    result['extra']['rpath_injection'] = dyn['rpath']
                if dyn.get('shared_libs'):
                    result['extra']['shared_libs'] = dyn['shared_libs']
            except Exception:
                pass
        # JWT scan on strings
        try:
            from mobsf.StaticAnalyzer.views.common.jwt_analysis import find_jwts_in_strings
            all_strings = [s if isinstance(s, str) else str(s)
                           for s in result.get('strings_sample', [])]
            result['jwt_findings'] = find_jwts_in_strings(all_strings)
        except Exception:
            result['jwt_findings'] = []
    except Exception as exc:
        logger.exception('Checksec failed for %s', path)
        result['error'] = str(exc)
    return result
