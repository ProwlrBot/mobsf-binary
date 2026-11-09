# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobsf.MobSF.utils import (
    get_scan_logs,
    is_md5,
)
from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.home import (
    RecentScans,
    Upload,
    delete_scan,
    search,
)
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.StaticAnalyzer.views.android.views import view_source
from mobsf.StaticAnalyzer.views.android.static_analyzer import static_analyzer
from mobsf.StaticAnalyzer.views.ios.views import view_source as ios_view_source
from mobsf.StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from mobsf.StaticAnalyzer.views.common.async_task import list_tasks
from mobsf.StaticAnalyzer.views.common.shared_func import compare_apps
from mobsf.StaticAnalyzer.views.common.suppression import (
    delete_suppression,
    list_suppressions,
    suppress_by_files,
    suppress_by_rule_id,
)
from mobsf.StaticAnalyzer.views.common.pdf import pdf
from mobsf.StaticAnalyzer.views.common.appsec import appsec_dashboard
from mobsf.StaticAnalyzer.views.windows import windows


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    checksum = request.POST['hash']
    if not is_md5(checksum):
        return make_api_response(
            {'error': 'Invalid Checksum'}, 500)
    robj = RecentScansDB.objects.filter(MD5=checksum)
    if not robj.exists():
        return make_api_response(
            {'error': 'The file is not uploaded/available'}, 500)
    scan_type = robj[0].SCAN_TYPE
    # APK, Source Code (Android/iOS) ZIP, SO, JAR, AAR
    if scan_type in settings.ANDROID_EXTS:
        resp = static_analyzer(request, checksum, True)
        if 'type' in resp:
            resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # IPA
    elif scan_type in settings.IOS_EXTS:
        resp = static_analyzer_ios(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    # APPX
    elif scan_type in settings.WINDOWS_EXTS:
        resp = windows.staticanalyzer_windows(request, checksum, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scan_logs(request):
    """POST - Get Scan logs."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = get_scan_logs(request.POST['hash'])
    if not resp:
        return make_api_response(
            {'error': 'No scan logs found'}, 400)
    return make_api_response({'logs': resp}, 200)


@request_method(['POST'])
@csrf_exempt
def api_tasks(request):
    """POST - Get Scan Queue."""
    resp = list_tasks(request, True)
    if not resp:
        return make_api_response(
            {'error': 'Scan queue empty'}, 400)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_scan(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'pdf_dat' in resp:
        response = HttpResponse(
            resp['pdf_dat'], content_type='application/pdf')
        response['Access-Control-Allow-Origin'] = '*'
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'PDF Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = pdf(
        request,
        request.POST['hash'],
        api=True,
        jsonres=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'report_dat' in resp:
        response = make_api_response(resp['report_dat'], 200)
    elif resp.get('report') == 'Report not Found':
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_search(request):
    """Search by checksum or text."""
    if 'query' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = search(request, api=True)
    if 'checksum' in resp:
        request.POST = {'hash': resp['checksum']}
        return api_json_report(request)
    elif 'error' in resp:
        return make_api_response(resp, 404)


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if not params.issubset(request.POST):
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if request.POST['type'] in {'eclipse', 'studio', 'flutter',
                                'apk', 'java', 'smali', 'xml'}:
        resp = view_source.run(request, api=True)
    else:
        resp = ios_view_source.run(request, api=True)
    status = resp.pop('_status_code', None)
    if 'error' in resp:
        response = make_api_response(resp, status or 400)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_compare(request):
    """Compare 2 apps."""
    params = {'hash1', 'hash2'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = compare_apps(
        request,
        request.POST['hash1'],
        request.POST['hash2'],
        True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_scorecard(request):
    """Generate App Score Card."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = appsec_dashboard(
        request,
        request.POST['hash'],
        api=True)
    if 'error' in resp:
        if resp.get('error') == 'Invalid scan hash':
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(resp, 500)
    elif 'hash' in resp:
        response = make_api_response(resp, 200)
    elif 'not_found' in resp:
        response = make_api_response(resp, 404)
    else:
        response = make_api_response(
            {'error': 'JSON Generation Error'}, 500)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_rule_id(request):
    """POST - Suppress a rule by id."""
    params = {'rule', 'type', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_rule_id(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_suppress_by_files(request):
    """POST - Suppress a rule by files."""
    params = {'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = suppress_by_files(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_list_suppressions(request):
    """POST - View Suppressions."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = list_suppressions(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_suppression(request):
    """POST - Delete a suppression."""
    params = {'kind', 'type', 'rule', 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = delete_suppression(request, True)
    if 'error' in resp:
        response = make_api_response(resp, 500)
    else:
        response = make_api_response(resp, 200)
    return response


@request_method(['POST'])
@csrf_exempt
def api_sbom_cves(request):
    """POST - Correlate SBOM entries with CVEs via OSV.dev.

    POST body (JSON or form):
      entries  - list of {"name": str, "version": str} dicts
      ecosystem - optional override (e.g. "Maven", "npm")
    """
    import json as _json
    from mobsf.StaticAnalyzer.views.common.sbom_cve import correlate_sbom_cves
    try:
        raw = request.body
        if raw:
            data = _json.loads(raw)
        else:
            data = request.POST.dict()
        entries = data.get('entries', [])
        ecosystem = data.get('ecosystem', '')
        if not isinstance(entries, list):
            return make_api_response({'error': 'entries must be a list'}, 422)
        result = correlate_sbom_cves(entries, ecosystem_hint=ecosystem)
        return make_api_response(result, 200)
    except Exception as exp:
        return make_api_response({'error': str(exp)}, 500)


@request_method(['POST'])
@csrf_exempt
def api_jwt_analysis(request):
    """POST - Scan strings for embedded JWTs and audit security.

    POST body (JSON or form):
      strings - list of strings to scan for JWT tokens
    """
    import json as _json
    from mobsf.StaticAnalyzer.views.common.jwt_analysis import analyze_jwts
    try:
        raw = request.body
        if raw:
            data = _json.loads(raw)
        else:
            data = request.POST.dict()
        strings = data.get('strings', [])
        if not isinstance(strings, list):
            return make_api_response({'error': 'strings must be a list'}, 422)
        result = analyze_jwts(strings)
        return make_api_response(result, 200)
    except Exception as exp:
        return make_api_response({'error': str(exp)}, 500)


@request_method(['POST'])
@csrf_exempt
def api_vulnx_search(request):
    """POST - Search ProjectDiscovery vulnx for CVEs by tech stack.

    POST body (JSON or form):
      tech_stack - list of {"name": str, "version": str} dicts
      severity   - optional comma-separated filter (default: medium,high,critical)
    """
    import json as _json
    from mobsf.StaticAnalyzer.views.common.vulnx_bridge import (
        analyze_tech_stack,
        _vulnx_available,
    )
    if not _vulnx_available():
        return make_api_response(
            {'error': 'vulnx not available',
             'install': 'https://docs.projectdiscovery.io/tools/vulnx'}, 400)
    try:
        raw = request.body
        if raw:
            data = _json.loads(raw)
        else:
            data = request.POST.dict()
        tech_stack = data.get('tech_stack', [])
        severity = data.get('severity', 'medium,high,critical')
        if not isinstance(tech_stack, list):
            return make_api_response({'error': 'tech_stack must be a list'}, 422)
        result = analyze_tech_stack(tech_stack, severity_filter=severity)
        return make_api_response(result, 200)
    except Exception as exp:
        return make_api_response({'error': str(exp)}, 500)


@request_method(['POST'])
@csrf_exempt
def api_binary_findings(request):
    """POST - Aggregate on-demand binary security findings for a completed scan.

    Runs RPATH injection check on extracted ELF libs and returns a unified
    findings dict. Complements the stored report with live tool-bridge analysis.

    POST body:
      hash - MD5 scan hash
    """
    from pathlib import Path
    from mobsf.StaticAnalyzer.views.common.binary.tools_bridge import readelf_dynamic

    hash_val = request.POST.get('hash', '')
    if not hash_val or not is_md5(hash_val):
        return make_api_response({'error': 'Valid hash required'}, 422)

    scan_dir = Path(settings.UPLD_DIR) / hash_val
    if not scan_dir.exists():
        return make_api_response({'error': 'Scan not found'}, 404)

    native_exts = {'.so', '.dylib', '.dll', '.exe'}
    native_libs = [p for p in scan_dir.rglob('*') if p.suffix.lower() in native_exts]

    elf_rpath_findings = []
    try:
        for lib in native_libs:
            if lib.suffix == '.so':
                dyn = readelf_dynamic(str(lib))
                if dyn.get('rpath'):
                    elf_rpath_findings.append({
                        'lib': lib.name,
                        'rpath': dyn['rpath'],
                    })
    except Exception:
        pass

    result = {
        'hash': hash_val,
        'native_lib_count': len(native_libs),
        'native_libs': [str(p.relative_to(scan_dir)) for p in native_libs],
        'elf_rpath_findings': elf_rpath_findings,
        'hint': (
            'Use mobsf_get_native_paths MCP tool to get full paths for REA analysis. '
            'REA wraps Ghidra, Binary Ninja, r2, and frida for deep RE.'
        ),
    }
    return make_api_response(result, 200)


@request_method(['POST'])
@csrf_exempt
def api_triage(request):
    """POST - Run full triage pipeline on a completed scan.

    Runs fp_filter → llm_triage → masvs_coverage → triage_report.

    POST body (JSON or form):
      hash                  - MD5 scan hash (required)
      skip_llm              - force rule-based scoring (optional, default false)
      skip_noise_in_report  - omit noise findings from HTML report (optional)
    """
    import json as _json
    from mobsf.StaticAnalyzer.views.common.triage_pipeline import run_triage

    try:
        raw = request.body
        if raw:
            data = _json.loads(raw)
        else:
            data = request.POST.dict()
    except Exception:
        data = request.POST.dict()

    scan_hash = data.get('hash', '')
    if not scan_hash or not is_md5(scan_hash):
        return make_api_response({'error': 'Valid hash required'}, 422)

    skip_llm = bool(data.get('skip_llm', False))
    skip_noise = bool(data.get('skip_noise_in_report', False))

    # Resolve app metadata from DB
    app_info: dict = {}
    try:
        robj = RecentScansDB.objects.filter(MD5=scan_hash).first()
        if not robj:
            return make_api_response({'error': f'Scan {scan_hash} not found'}, 404)
        app_info = {
            'app_name': getattr(robj, 'APP_NAME', '') or getattr(robj, 'FILE_NAME', ''),
            'package': getattr(robj, 'PACKAGE_NAME', '') or '',
            'version': getattr(robj, 'VERSION_NAME', '') or '',
            'platform': getattr(robj, 'ANALYZER', '') or 'android',
        }
    except Exception:
        pass

    # Pull code analysis findings from Android model
    findings: list = []
    try:
        from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
        report_obj = StaticAnalyzerAndroid.objects.filter(MD5=scan_hash).first()
        if report_obj and getattr(report_obj, 'CODE_ANALYSIS', None):
            raw_ca = report_obj.CODE_ANALYSIS
            if isinstance(raw_ca, dict):
                for rule_id, item in raw_ca.items():
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
    except Exception:
        pass

    try:
        result = run_triage(
            findings,
            app_info=app_info,
            skip_llm=skip_llm,
            skip_noise_in_report=skip_noise,
        )
        return make_api_response({
            'hash': scan_hash,
            'stats': result['stats'],
            'coverage': result.get('coverage', {}).get('summary', {}),
            'gap_controls': result.get('coverage', {}).get('gap_controls', []),
            'llm_provider': result['llm_status'].get('provider', 'none'),
            'findings_count': len(result['findings']),
            'html_available': bool(result.get('html', '')),
        }, 200)
    except Exception as exp:
        return make_api_response({'error': str(exp)}, 500)
