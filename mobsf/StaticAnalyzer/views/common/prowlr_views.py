# -*- coding: utf_8 -*-
"""ProwlrBot UI views — Settings + Triage dashboard."""
import json
import logging
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_POST, require_http_methods

from mobsf.MobSF.views.authorization import has_permission, Permissions

logger = logging.getLogger(__name__)

LLM_CFG_PATH = Path.home() / '.config' / 'mobsf' / 'llm.json'

PROVIDERS = ['auto', 'lmstudio', 'ollama', 'openai', 'anthropic', 'none']


def _base_ctx(extra=None):
    ctx = {'version': settings.MOBSF_VER}
    if extra:
        ctx.update(extra)
    return ctx


def _load_llm_cfg() -> dict:
    defaults = {
        'provider': 'auto', 'base_url': '', 'model': '',
        'api_key': '', 'timeout': 30,
    }
    if LLM_CFG_PATH.exists():
        try:
            defaults.update(json.loads(LLM_CFG_PATH.read_text()))
        except Exception:
            pass
    return defaults


# ─── Settings ──────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(['GET', 'POST'])
def prowlr_settings(request):
    cfg = _load_llm_cfg()
    saved = False
    error = None

    if request.method == 'POST':
        try:
            new_cfg = {
                'provider': request.POST.get('provider', 'auto'),
                'base_url': request.POST.get('base_url', '').strip(),
                'model':    request.POST.get('model', '').strip(),
                'timeout':  int(request.POST.get('timeout', 30) or 30),
            }
            # Only update API key if one was submitted (don't wipe existing)
            submitted_key = request.POST.get('api_key', '').strip()
            if submitted_key:
                new_cfg['api_key'] = submitted_key
            else:
                new_cfg['api_key'] = cfg.get('api_key', '')

            LLM_CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
            LLM_CFG_PATH.write_text(json.dumps(new_cfg, indent=2))
            cfg = new_cfg
            saved = True
        except Exception as exc:
            error = str(exc)

    # Get provider status
    try:
        from mobsf.StaticAnalyzer.views.common.llm_triage import get_provider_status
        status = get_provider_status()
    except Exception:
        status = {}

    return render(request, 'prowlr/settings.html', _base_ctx({
        'cfg': cfg,
        'providers': PROVIDERS,
        'status': status,
        'saved': saved,
        'error': error,
    }))


# ─── Triage ────────────────────────────────────────────────────────────────────

@login_required
def triage_view(request, scan_hash=None):
    """Show triage UI for a completed scan."""
    # Recent scans list for the picker
    recent = []
    try:
        from mobsf.MobSF.models import RecentScansDB
        recent = list(RecentScansDB.objects.order_by('-TIMESTAMP').values(
            'MD5', 'FILE_NAME', 'APP_NAME', 'ANALYZER', 'TIMESTAMP')[:30])
    except Exception:
        pass

    result = None
    scan_info = None
    err = None

    if scan_hash and request.method == 'POST':
        skip_llm = 'skip_llm' in request.POST
        skip_noise = 'skip_noise' in request.POST
        try:
            from mobsf.StaticAnalyzer.views.common.triage_pipeline import run_triage
            from mobsf.MobSF.models import RecentScansDB

            robj = RecentScansDB.objects.filter(MD5=scan_hash).first()
            if not robj:
                err = f'Scan {scan_hash} not found'
            else:
                app_info = {
                    'app_name': getattr(robj, 'APP_NAME', '') or getattr(robj, 'FILE_NAME', ''),
                    'package':  getattr(robj, 'PACKAGE_NAME', '') or '',
                    'version':  getattr(robj, 'VERSION_NAME', '') or '',
                    'platform': getattr(robj, 'ANALYZER', '') or 'android',
                }
                findings = _pull_findings(scan_hash)
                result = run_triage(
                    findings=findings,
                    app_info=app_info,
                    skip_llm=skip_llm,
                    skip_noise_in_report=skip_noise,
                )
                scan_info = app_info
        except Exception as exc:
            logger.exception('Triage error')
            err = str(exc)

    elif scan_hash and request.method == 'GET':
        try:
            from mobsf.MobSF.models import RecentScansDB
            robj = RecentScansDB.objects.filter(MD5=scan_hash).first()
            if robj:
                scan_info = {
                    'app_name': getattr(robj, 'APP_NAME', '') or getattr(robj, 'FILE_NAME', ''),
                    'package':  getattr(robj, 'PACKAGE_NAME', '') or '',
                    'platform': getattr(robj, 'ANALYZER', '') or 'android',
                }
        except Exception:
            pass

    # LLM status badge
    try:
        from mobsf.StaticAnalyzer.views.common.llm_triage import get_provider_status
        llm_status = get_provider_status()
    except Exception:
        llm_status = {}

    return render(request, 'prowlr/triage.html', _base_ctx({
        'recent': recent,
        'scan_hash': scan_hash,
        'scan_info': scan_info,
        'result': result,
        'llm_status': llm_status,
        'error': err,
    }))


def _pull_findings(scan_hash: str) -> list:
    """Extract code-analysis findings from the Android static analyzer DB."""
    findings = []
    try:
        from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
        obj = StaticAnalyzerAndroid.objects.filter(MD5=scan_hash).first()
        if obj and getattr(obj, 'CODE_ANALYSIS', None):
            ca = obj.CODE_ANALYSIS
            if isinstance(ca, dict):
                for rule_id, item in ca.items():
                    if not isinstance(item, dict):
                        continue
                    meta = item.get('metadata', {})
                    findings.append({
                        'title':       meta.get('description', rule_id),
                        'description': meta.get('description', ''),
                        'rule_id':     rule_id,
                        'severity':    meta.get('severity', 'info'),
                        'file_path':   '',
                        'code':        '',
                    })
    except Exception:
        pass
    return findings
