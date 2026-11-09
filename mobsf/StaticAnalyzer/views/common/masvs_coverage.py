#!/usr/bin/python
# coding=utf-8
"""
MASVS v2.1 coverage mapping for MobSF findings.

Maps every MASVS v2.1 control to the MobSF rule IDs, finding patterns,
and analysis modules that test for it. Produces a coverage report and
tags each finding with its MASVS control ID.

Usage:
    from mobsf.StaticAnalyzer.views.common.masvs_coverage import (
        tag_findings_with_masvs,
        coverage_report,
        MASVS_CONTROLS,
    )
    tagged = tag_findings_with_masvs(findings)
    report = coverage_report(tagged)
"""
import re
from dataclasses import dataclass, field
from typing import Literal

Category = Literal[
    'STORAGE', 'CRYPTO', 'AUTH', 'NETWORK',
    'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY',
]

CATEGORY_COLOR = {
    'STORAGE':    '#4a9eff',
    'CRYPTO':     '#a855f7',
    'AUTH':       '#f97316',
    'NETWORK':    '#14b8a6',
    'PLATFORM':   '#06b6d4',
    'CODE':       '#22c55e',
    'RESILIENCE': '#e4f222',
    'PRIVACY':    '#ec4899',
}


@dataclass
class MASVSControl:
    id: str
    category: Category
    title: str
    description: str
    detection_patterns: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    coverage: Literal['full', 'partial', 'gap'] = 'gap'
    coverage_notes: str = ''


MASVS_CONTROLS: list[MASVSControl] = [
    MASVSControl(
        id='STORAGE-1',
        category='STORAGE',
        title='Sensitive data storage',
        description='App does not store sensitive data insecurely',
        detection_patterns=[
            r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
            r'SharedPreferences.*password|SharedPreferences.*token',
            r'External Storage|getExternalStorage',
            r'SQLite.*password|SQLite.*cleartext',
            r'Log\.[vdiwef].*(?:password|token|key|secret)',
        ],
        rule_ids=['android_world_read_write_permission', 'android_logging', 'android_sqlcipher'],
        coverage='partial',
        coverage_notes='SharedPrefs, external storage, logging detected. SQLCipher enforcement missing.',
    ),
    MASVSControl(
        id='STORAGE-2',
        category='STORAGE',
        title='Data leakage prevention',
        description='App prevents data leakage via backups, screenshots, IPC',
        detection_patterns=[
            r'allowBackup.*true|android:allowBackup',
            r'FLAG_SECURE',
            r'ClipboardManager|CLIPBOARD_SERVICE',
            r'KeyboardCache|android:inputType',
        ],
        rule_ids=['android_allow_backup'],
        coverage='partial',
        coverage_notes='allowBackup detected. FLAG_SECURE absence and clipboard sniffing not checked.',
    ),
    MASVSControl(
        id='CRYPTO-1',
        category='CRYPTO',
        title='Strong current cryptographic algorithms',
        description='No MD5/SHA1/DES/AES-ECB, no hardcoded IVs',
        detection_patterns=[
            r'MessageDigest.*MD5|MessageDigest.*SHA-1',
            r'\bDES\b|RC4|RC2|Blowfish',
            r'AES.*ECB|/ECB/',
            r'IvParameterSpec.*new byte|hardcoded.*IV',
            r'getInstance.*DES|getInstance.*MD5|getInstance.*SHA1',
        ],
        rule_ids=['android_insecure_random', 'android_weak_crypto', 'android_des', 'android_md5'],
        coverage='full',
        coverage_notes='Weak algorithm detection fully covered by MobSF SAST rules.',
    ),
    MASVSControl(
        id='CRYPTO-2',
        category='CRYPTO',
        title='Key management best practices',
        description='No hardcoded keys, KeyStore used for key storage',
        detection_patterns=[
            r'SecretKeySpec.*new byte|hardcoded.*key',
            r'AESKeySpec|DESKeySpec',
            r'AndroidKeyStore',
            r'KeyGenerator.*AES',
        ],
        rule_ids=['android_hardcoded_key'],
        coverage='partial',
        coverage_notes='Hardcoded key patterns detected. KeyStore usage verification not implemented.',
    ),
    MASVSControl(
        id='AUTH-1',
        category='AUTH',
        title='Secure authentication protocols',
        description='OAuth PKCE required, no implicit flow, no hardcoded credentials',
        detection_patterns=[
            r'response_type=token|response_type%3Dtoken',
            r'oauth.*implicit|grant_type.*token',
            r'password.*=.*"[^"]{6,}"|api_key.*=.*"[^"]{10,}"',
            r'code_challenge|PKCE',
        ],
        rule_ids=['android_oauth_implicit_flow', 'android_oauth_no_pkce', 'android_hardcoded_username'],
        coverage='partial',
        coverage_notes='OAuth implicit flow + PKCE rules added. Hardcoded password patterns in MobSF base.',
    ),
    MASVSControl(
        id='AUTH-2',
        category='AUTH',
        title='Identity verification before sensitive operations',
        description='App verifies user identity before data-modifying ops',
        detection_patterns=[
            r'authentication|biometric|fingerprint',
            r'BiometricPrompt|FingerprintManager',
        ],
        rule_ids=[],
        coverage='gap',
        coverage_notes='No static detection for missing auth checks before sensitive ops. Dynamic analysis required.',
    ),
    MASVSControl(
        id='AUTH-3',
        category='AUTH',
        title='Step-up authentication for high-risk ops',
        description='High-risk operations require re-authentication',
        detection_patterns=[
            r'payment|transfer|delete.*account|change.*password',
            r'confirmCredentials|createConfirmDeviceCredentialIntent',
        ],
        rule_ids=[],
        coverage='gap',
        coverage_notes='Step-up auth requires dynamic analysis. Static: flag payment/transfer ops without re-auth checks.',
    ),
    MASVSControl(
        id='NETWORK-1',
        category='NETWORK',
        title='Secure network traffic',
        description='HTTPS everywhere, no cleartext, TLS 1.2+',
        detection_patterns=[
            r'http://(?!localhost|127\.0\.0\.1)',
            r'cleartext|allowCleartextTraffic.*true',
            r'usesCleartextTraffic|android:usesCleartextTraffic',
            r'SSLv3|TLSv1\.0|TLSv1\.1',
        ],
        rule_ids=['android_clear_text', 'android_insecure_connection'],
        coverage='full',
        coverage_notes='Cleartext traffic, NSC, and HTTP URL detection fully covered.',
    ),
    MASVSControl(
        id='NETWORK-2',
        category='NETWORK',
        title='Endpoint identity verification',
        description='Certificate pinning, hostname validation',
        detection_patterns=[
            r'TrustAllCerts|X509TrustManager',
            r'ALLOW_ALL_HOSTNAME_VERIFIER|onReceivedSslError.*proceed',
            r'getAcceptedIssuers.*null|checkServerTrusted.*empty',
            r'certificate.*pinning|CertificatePinner',
        ],
        rule_ids=['android_trust_all_ssl', 'android_insecure_hostname_verifier'],
        coverage='full',
        coverage_notes='SSL bypass and trust-all patterns fully covered by MobSF base rules.',
    ),
    # PLATFORM: 3 controls per MASVS v2.1.0 official PDF
    MASVSControl(
        id='PLATFORM-1',
        category='PLATFORM',
        title='IPC mechanisms used securely',
        description='Exported components protected; PendingIntents immutable; deep links validated; ContentProviders secured',
        detection_patterns=[
            r'exported.*true|android:exported',
            r'PendingIntent.*FLAG_IMMUTABLE|FLAG_MUTABLE',
            r'ContentProvider.*exported|grantUriPermissions',
            r'deeplink|deep.link|intent.filter.*browsable',
            r'loadUrl.*getQueryParameter|loadUrl.*getData',
            r'SchemeHandler|UriHandler',
        ],
        rule_ids=[
            'android_exported',
            'android_pending_intent_mutable',
            'android_pending_intent_implicit',
            'android_deeplink_param_injection',
            'android_deeplink_scheme_handler',
        ],
        coverage='partial',
        coverage_notes='Exported components, PendingIntent mutability, deep link injection covered. ContentProvider URI grant analysis partial.',
    ),
    MASVSControl(
        id='PLATFORM-2',
        category='PLATFORM',
        title='WebViews used securely',
        description='No JS bridge exposure to untrusted origins; no loadUrl with attacker-controlled input',
        detection_patterns=[
            r'addJavascriptInterface|setJavaScriptEnabled',
            r'loadUrl.*intent|loadUrl.*getQueryParameter|loadUrl.*getData',
            r'WebView.*setAllowFileAccess|WebView.*setAllowUniversalAccessFromFileURLs',
            r'onReceivedSslError.*proceed|setWebContentsDebuggingEnabled.*true',
        ],
        rule_ids=['android_js_interface', 'android_webview_external', 'android_webview_ignore_ssl'],
        coverage='partial',
        coverage_notes='JS bridge and file-access WebView rules covered. Dynamic content injection needs taint analysis.',
    ),
    MASVSControl(
        id='PLATFORM-3',
        category='PLATFORM',
        title='User interface used securely',
        description='FLAG_SECURE on sensitive screens; AutoFill disabled on sensitive fields; keyboard caching prevented',
        detection_patterns=[
            r'FLAG_SECURE|WindowManager\.LayoutParams\.FLAG_SECURE',
            r'addFlags.*FLAG_SECURE|setFlags.*FLAG_SECURE',
            r'importantForAutofill|IMPORTANT_FOR_AUTOFILL_NO',
            r'AUTOFILL_HINT_CREDIT_CARD|autofillHints.*creditCard',
            r'inputType.*textNoSuggestions|IME_FLAG_NO_PERSONALIZED_LEARNING',
        ],
        rule_ids=[
            'android_no_flag_secure',
            'android_flag_secure_present',
            'android_autofill_credit_card_hint',
            'android_important_for_autofill_no',
            'android_keyboard_cache_sensitive',
        ],
        coverage='partial',
        coverage_notes='FLAG_SECURE absence detection added for sensitive Activities. AutoFill credit card hint + keyboard cache rules added. Layout XML analysis not implemented.',
    ),
    MASVSControl(
        id='CODE-1',
        category='CODE',
        title='Current platform version required',
        description='minSdkVersion >= 28 (Android 9)',
        detection_patterns=[
            r'minSdkVersion.*[0-9]+',
            r'android:minSdkVersion',
        ],
        rule_ids=['android_sdk_version'],
        coverage='full',
        coverage_notes='SDK version analysis fully covered by MobSF manifest analysis.',
    ),
    MASVSControl(
        id='CODE-2',
        category='CODE',
        title='No known vulnerable components',
        description='SBOM CVE correlation — no deps with known CVEs',
        detection_patterns=[
            r'CVE-\d{4}-\d+',
            r'vulnerability|known.*exploit',
        ],
        rule_ids=['sbom_cve'],
        coverage='full',
        coverage_notes='OSV.dev + vulnx SBOM correlation fully implemented.',
    ),
    MASVSControl(
        id='CODE-3',
        category='CODE',
        title='Minimal functionality',
        description='No debug builds, no test/dev functionality shipped',
        detection_patterns=[
            r'BuildConfig\.DEBUG.*true|isDebuggable',
            r'android:debuggable.*true',
            r'StrictMode|android\.util\.Log\.d',
        ],
        rule_ids=['android_debuggable'],
        coverage='full',
        coverage_notes='Debuggable flag and debug build patterns covered.',
    ),
    MASVSControl(
        id='CODE-4',
        category='CODE',
        title='Security controls enforced server-side',
        description='Client-side security controls not bypassable',
        detection_patterns=[
            r'skipAuth|bypassAuth|isAdmin.*true',
            r'TODO.*auth|FIXME.*auth',
        ],
        rule_ids=[],
        coverage='gap',
        coverage_notes='Server-side enforcement requires dynamic testing. Static: flag client-only auth bypass patterns.',
    ),
    MASVSControl(
        id='RESILIENCE-1',
        category='RESILIENCE',
        title='Platform integrity validation',
        description='Root/jailbreak detection implemented',
        detection_patterns=[
            r'isRooted|RootBeer|RootChecker',
            r'su.*binary|/system/bin/su',
            r'PlayIntegrity|integrityToken',
            r'android_play_integrity|android_xposed_no_detect',
        ],
        rule_ids=['android_play_integrity', 'android_xposed_no_detect'],
        coverage='partial',
        coverage_notes='Play Integrity + Xposed detection rules added. Missing: RootBeer library check.',
    ),
    MASVSControl(
        id='RESILIENCE-2',
        category='RESILIENCE',
        title='Anti-tampering mechanisms',
        description='Signature verification, integrity check at runtime',
        detection_patterns=[
            r'getSignatures|PackageManager.*signatures',
            r'certificate.*check|SIGNED_BY',
            r'signing_security|janus_vulnerable',
        ],
        rule_ids=['signing_security'],
        coverage='partial',
        coverage_notes='Signing scheme analysis (V1/V2/V3/V4) + Janus detection implemented.',
    ),
    MASVSControl(
        id='RESILIENCE-3',
        category='RESILIENCE',
        title='Anti-static analysis',
        description='Obfuscation, string encryption, ProGuard/R8',
        detection_patterns=[
            r'ProGuard|R8|obfuscat',
            r'-keep.*class|dontwarn',
        ],
        rule_ids=['android_obfuscation'],
        coverage='gap',
        coverage_notes='Obfuscation presence not checked. Flag if class names are un-minified in a release build.',
    ),
    MASVSControl(
        id='RESILIENCE-4',
        category='RESILIENCE',
        title='Anti-dynamic analysis',
        description='Debugger detection, Frida detection',
        detection_patterns=[
            r'Debug\.isDebuggerConnected|ptrace',
            r'frida|gadget|__frida',
            r'anti.?debug|isDebugging',
            r'android_magisk_no_detect|android_xposed_detect',
        ],
        rule_ids=['android_magisk_no_detect', 'android_xposed_detect'],
        coverage='partial',
        coverage_notes='Xposed/Magisk detection rules added. Frida gadget detection not implemented.',
    ),
    # PRIVACY: 4 controls per MASVS v2.1.0 official PDF
    MASVSControl(
        id='PRIVACY-1',
        category='PRIVACY',
        title='Minimizes access to sensitive data',
        description='App requests only necessary permissions; no over-broad data collection',
        detection_patterns=[
            r'READ_CALL_LOG|READ_CONTACTS|READ_SMS|READ_CALENDAR',
            r'ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION',
            r'android\.permission\.',
            r'dangerous.*permission',
        ],
        rule_ids=['android_permission'],
        coverage='partial',
        coverage_notes='Dangerous permissions flagged. Over-collection requires data-flow analysis beyond SAST.',
    ),
    MASVSControl(
        id='PRIVACY-2',
        category='PRIVACY',
        title='Prevents identification of the user',
        description='No persistent device identifiers (IMEI, MAC, advertising ID) collected without consent',
        detection_patterns=[
            r'getDeviceId|TelephonyManager.*getDeviceId',
            r'READ_PHONE_STATE|IMEI',
            r'AdvertisingIdClient|getAdvertisingId',
            r'Settings\.Secure\.ANDROID_ID',
            r'getHardwareAddress|BLUETOOTH.*ADDRESS',
        ],
        rule_ids=['android_device_fingerprinting', 'android_advertising_id'],
        coverage='partial',
        coverage_notes='Device fingerprinting and advertising ID collection rules added. Consent gate enforcement requires runtime analysis.',
    ),
    MASVSControl(
        id='PRIVACY-3',
        category='PRIVACY',
        title='Transparent about data collection',
        description='App includes a privacy policy and discloses what data is collected',
        detection_patterns=[
            r'privacy.*policy|privacyPolicy|privacy_policy',
            r'PrivacyActivity|PrivacyFragment',
        ],
        rule_ids=[],
        coverage='gap',
        coverage_notes='Privacy policy presence not detectable by SAST alone. Requires manifest intent-filter or UI analysis.',
    ),
    MASVSControl(
        id='PRIVACY-4',
        category='PRIVACY',
        title='User has control over their own data',
        description='App provides delete-account, data-export, or opt-out mechanisms',
        detection_patterns=[
            r'deleteAccount|delete.*account|account.*delete',
            r'exportData|data.*export|optOut|opt.?out',
            r'MANAGE_ACCOUNTS|GET_ACCOUNTS',
        ],
        rule_ids=[],
        coverage='gap',
        coverage_notes='Account-deletion and data-export flows not detectable by manifest or code pattern scan alone.',
    ),
]

_CONTROL_BY_ID: dict[str, MASVSControl] = {c.id: c for c in MASVS_CONTROLS}

_COMPILED: list[tuple[MASVSControl, list[re.Pattern]]] = [
    (ctrl, [re.compile(p, re.IGNORECASE) for p in ctrl.detection_patterns])
    for ctrl in MASVS_CONTROLS
    if ctrl.detection_patterns
]


def tag_finding_with_masvs(finding: dict) -> dict:
    """Tag a single finding with matching MASVS v2.1 control IDs."""
    combined = ' '.join([
        finding.get('title', ''),
        finding.get('description', '') or finding.get('message', ''),
        finding.get('rule_id', '') or finding.get('title', ''),
        finding.get('file_path', '') or finding.get('file', ''),
    ])
    matched = set()
    for ctrl, patterns in _COMPILED:
        for pat in patterns:
            if pat.search(combined):
                matched.add(ctrl.id)
                break
    finding['masvs_ids'] = sorted(matched)
    if matched and 'masvs_category' not in finding:
        first = next((c for c in MASVS_CONTROLS if c.id in matched), None)
        if first:
            finding['masvs_category'] = first.category
            finding['masvs_color'] = CATEGORY_COLOR.get(first.category, '#666')
    return finding


def tag_findings_with_masvs(findings: list[dict]) -> list[dict]:
    """Tag all findings with MASVS control IDs."""
    for f in findings:
        tag_finding_with_masvs(f)
    return findings


def coverage_report(findings: list[dict] | None = None) -> dict:
    """
    Generate a MASVS v2.1 coverage report.

    Returns:
        {
            "controls": [{id, title, coverage, coverage_notes, finding_count, color}],
            "summary": {total, full, partial, gap, coverage_pct},
            "gap_controls": [list of gap control IDs],
        }
    """
    finding_counts: dict[str, int] = {c.id: 0 for c in MASVS_CONTROLS}
    if findings:
        for f in findings:
            for mid in f.get('masvs_ids', []):
                if mid in finding_counts:
                    finding_counts[mid] += 1

    controls_out = []
    for ctrl in MASVS_CONTROLS:
        controls_out.append({
            'id': ctrl.id,
            'category': ctrl.category,
            'title': ctrl.title,
            'description': ctrl.description,
            'coverage': ctrl.coverage,
            'coverage_notes': ctrl.coverage_notes,
            'finding_count': finding_counts[ctrl.id],
            'color': CATEGORY_COLOR.get(ctrl.category, '#666'),
        })

    total = len(MASVS_CONTROLS)
    full_count = sum(1 for c in MASVS_CONTROLS if c.coverage == 'full')
    partial_count = sum(1 for c in MASVS_CONTROLS if c.coverage == 'partial')
    gap_count = sum(1 for c in MASVS_CONTROLS if c.coverage == 'gap')

    return {
        'controls': controls_out,
        'summary': {
            'total': total,
            'full': full_count,
            'partial': partial_count,
            'gap': gap_count,
            'coverage_pct': round((full_count + partial_count * 0.5) / total * 100, 1),
        },
        'gap_controls': [c.id for c in MASVS_CONTROLS if c.coverage == 'gap'],
    }


def get_control(masvs_id: str) -> MASVSControl | None:
    """Look up a MASVS control by ID."""
    return _CONTROL_BY_ID.get(masvs_id)
