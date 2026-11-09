#!/usr/bin/python
# coding=utf-8
"""
Rule-based false-positive filter for MobSF findings.

Eliminates confirmed noise patterns before the LLM triage pass,
reducing API calls and analysis time. Based on the evidence-first
validation framework: a finding requires attacker control, a crossed
security boundary, AND demonstrated impact — not just pattern detection.
"""
import re
import logging
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

Verdict = Literal['noise', 'investigate', 'likely_fp', 'signal']


@dataclass
class FPResult:
    verdict: Verdict
    confidence: int          # 0–100 confidence in this verdict
    reason: str
    rule_id: str = ''
    bounty_ceiling: int = 0  # max realistic bounty score (0 = $0, 100 = critical)


# ── Never-report-standalone patterns ────────────────────────────────────────

NOISE_RULES = [
    # Anti-debug / anti-VM — legitimate anti-tamper, not a vulnerability
    {
        'id': 'NOISE-001',
        'name': 'anti_debug_antivm',
        'patterns': [
            r'Debug\.isDebuggerConnected',
            r'Build\.(FINGERPRINT|MANUFACTURER|HARDWARE|TAGS)',
            r'isDebuggerConnected|anti.?debug|anti.?vm|anti.?tamper',
        ],
        'reason': 'Anti-debug/anti-VM is legitimate app hardening (MASVS-RESILIENCE). Not a vulnerability standalone.',
        'bounty_ceiling': 0,
    },
    # Missing HTTP headers — no bounty on H1/Bugcrowd standalone
    {
        'id': 'NOISE-002',
        'name': 'missing_headers',
        'patterns': [
            r'X-Frame-Options|Content-Security-Policy|HSTS|Strict-Transport-Security',
            r'X-Content-Type-Options|Referrer-Policy|Permissions-Policy',
        ],
        'reason': 'Missing HTTP headers are explicitly excluded from most programs. No standalone bounty.',
        'bounty_ceiling': 0,
    },
    # IP disclosure without internal/metadata endpoint indication
    {
        'id': 'NOISE-003',
        'name': 'ip_disclosure_generic',
        'patterns': [
            r'IP[_ ]?[Aa]ddress.*(?:found|detected)',
            r'found.*\b(?:192\.168|10\.\d|172\.(?:1[6-9]|2\d|3[01]))\.',
        ],
        'reason': 'IP disclosure is noise unless it exposes cloud metadata (169.254.169.254) or unreachable internal infra.',
        'bounty_ceiling': 10,
    },
    # Weak crypto in non-security context (UI, media, checksums)
    {
        'id': 'NOISE-004',
        'name': 'weak_hash_nonsec_context',
        'patterns': [
            r'MD5.*(?:image|avatar|sticker|cache|thumb|icon|color)',
            r'(?:image|avatar|sticker|cache).*MD5',
        ],
        'reason': 'MD5/SHA1 for media/cache checksums is not a security vulnerability.',
        'bounty_ceiling': 0,
    },
    # Predictable random in non-security context
    {
        'id': 'NOISE-005',
        'name': 'weak_random_nonsec',
        'patterns': [
            r'(?:new Random|Math\.random).*(?:color|position|animation|shuffle|sticker|offset)',
            r'(?:color|position|animation|shuffle|sticker).*(?:new Random|Math\.random)',
        ],
        'reason': 'java.util.Random for UI/animation is not a security issue. Only flag if used for tokens/sessions.',
        'bounty_ceiling': 0,
    },
    # Debug logging without evidence of sensitive data
    {
        'id': 'NOISE-006',
        'name': 'debug_logging_generic',
        'patterns': [
            r'Log\.[vdiwef]\(.*TAG.*\)',
            r'System\.out\.print',
        ],
        'reason': 'Debug logging is noise unless it logs tokens, passwords, or PII. Needs content inspection.',
        'bounty_ceiling': 5,
    },
    # App sandbox writes — normal sandboxed file I/O
    {
        'id': 'NOISE-007',
        'name': 'app_sandbox_write',
        'patterns': [
            r'(?:openFileOutput|getFilesDir|getCacheDir).*MODE_PRIVATE',
        ],
        'reason': 'MODE_PRIVATE file writes are sandbox-protected. Not externally accessible.',
        'bounty_ceiling': 0,
    },
    # SafetyNet deprecated warning — only interesting if MISSING, not present
    {
        'id': 'NOISE-008',
        'name': 'safetynet_present',
        'patterns': [
            r'SafetyNetClient|SafetyNet\.getClient',
        ],
        'reason': 'SafetyNet is deprecated (May 2024) but its presence is not exploitable. Flag its absence for root bypass risk.',
        'bounty_ceiling': 10,
    },
]

# ── High-signal patterns that need investigation ──────────────────────────────

SIGNAL_RULES = [
    {
        'id': 'SIGNAL-001',
        'name': 'exported_activity_with_url',
        'patterns': [
            r'exported.*(?:http|https|loadUrl|WebView)',
            r'(?:DeepLink|Browser|OAuth|Auth|Login)Activity',
        ],
        'reason': 'Exported activity handling URLs or OAuth — investigate for redirect/auth bypass.',
        'bounty_ceiling': 80,
    },
    {
        'id': 'SIGNAL-002',
        'name': 'webview_js_with_bridge',
        'patterns': [
            r'addJavascriptInterface',
            r'setJavaScriptEnabled.*true',
        ],
        'reason': 'JavaScript bridge in WebView — check if attacker-controlled URL can reach the bridge.',
        'bounty_ceiling': 90,
    },
    {
        'id': 'SIGNAL-003',
        'name': 'raw_sql_concatenation',
        'patterns': [
            r'rawQuery\s*\([^?]*\+',
            r'execSQL\s*\([^?]*\+',
        ],
        'reason': 'String concatenation in SQL query — potential SQLi if input is attacker-controlled.',
        'bounty_ceiling': 85,
    },
    {
        'id': 'SIGNAL-004',
        'name': 'cloud_metadata_ssrf',
        'patterns': [
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'instance-data\.ec2\.internal',
        ],
        'reason': 'Cloud metadata endpoint reference — potential SSRF to instance metadata.',
        'bounty_ceiling': 95,
    },
    {
        'id': 'SIGNAL-005',
        'name': 'hardcoded_private_key',
        'patterns': [
            r'-----BEGIN (RSA |EC |PRIVATE )?PRIVATE KEY-----',
            r'PRIVATE KEY',
        ],
        'reason': 'Hardcoded private key in binary — confirm it is not a test key.',
        'bounty_ceiling': 95,
    },
    {
        'id': 'SIGNAL-006',
        'name': 'pending_intent_mutable',
        'patterns': [
            r'PendingIntent\.(getActivity|getBroadcast|getService)',
        ],
        'reason': 'PendingIntent — check for FLAG_IMMUTABLE. Mutable PendingIntents enable intent hijacking.',
        'bounty_ceiling': 70,
    },
    {
        'id': 'SIGNAL-007',
        'name': 'oauth_implicit_flow',
        'patterns': [
            r'response_type=token',
            r'response_type%3Dtoken',
        ],
        'reason': 'OAuth implicit flow — deprecated, tokens in redirect URI. High bounty if exploitable.',
        'bounty_ceiling': 85,
    },
    {
        'id': 'SIGNAL-008',
        'name': 'firebase_no_auth',
        'patterns': [
            r'firebaseio\.com',
            r'firebase.*database.*url',
        ],
        'reason': 'Firebase URL found — test database rules for unauthenticated read/write.',
        'bounty_ceiling': 90,
    },
]

# ── Context boosters — keywords that elevate any adjacent finding ─────────────

HIGH_VALUE_CONTEXT = [
    r'access_token|auth_token|bearer|jwt|session|credential',
    r'payment|billing|card|ssn|social.?security',
    r'admin|superuser|privilege|role.*admin',
    r'private.?key|client.?secret|api.?secret',
]


def _matches_any(text: str, patterns: list) -> bool:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def _has_high_value_context(text: str) -> bool:
    return _matches_any(text, HIGH_VALUE_CONTEXT)


def classify_finding(
    finding_text: str,
    finding_title: str = '',
    file_path: str = '',
    code_snippet: str = '',
) -> FPResult:
    """
    Rule-based FP classification for a single MobSF finding.

    Args:
        finding_text:  MobSF finding description / message
        finding_title: short title / rule name
        file_path:     source file path of the finding
        code_snippet:  relevant code context (10-50 lines around the flag)

    Returns:
        FPResult with verdict, confidence, reason, and bounty ceiling
    """
    combined = f'{finding_title} {finding_text} {file_path} {code_snippet}'

    # 1. Check noise rules first
    for rule in NOISE_RULES:
        if _matches_any(combined, rule['patterns']):
            # Noise with high-value context nearby? Downgrade to investigate
            if _has_high_value_context(combined):
                return FPResult(
                    verdict='investigate',
                    confidence=50,
                    reason=f"{rule['reason']} BUT high-value context nearby — verify manually.",
                    rule_id=rule['id'],
                    bounty_ceiling=rule['bounty_ceiling'] + 20,
                )
            return FPResult(
                verdict='noise',
                confidence=85,
                reason=rule['reason'],
                rule_id=rule['id'],
                bounty_ceiling=rule['bounty_ceiling'],
            )

    # 2. Check signal rules
    for rule in SIGNAL_RULES:
        if _matches_any(combined, rule['patterns']):
            ceiling = rule['bounty_ceiling']
            if _has_high_value_context(combined):
                ceiling = min(ceiling + 10, 100)
            return FPResult(
                verdict='signal',
                confidence=70,
                reason=rule['reason'],
                rule_id=rule['id'],
                bounty_ceiling=ceiling,
            )

    # 3. Unknown — needs LLM or manual review
    return FPResult(
        verdict='investigate',
        confidence=30,
        reason='No matching rule — needs manual review or LLM analysis.',
        rule_id='UNKNOWN',
        bounty_ceiling=50,
    )


def filter_findings(findings: list) -> list:
    """
    Run the FP filter over a list of MobSF finding dicts.

    Each finding dict is expected to have at minimum:
        {"title": str, "description": str, "file_path": str, "code": str}

    Returns the same list with an added "fp_filter" key on each entry.
    """
    for finding in findings:
        text = finding.get('description', '') or finding.get('message', '') or ''
        title = finding.get('title', '') or finding.get('rule_id', '')
        path = finding.get('file_path', '') or finding.get('file', '')
        code = finding.get('code', '') or finding.get('snippet', '')
        result = classify_finding(text, title, path, code)
        finding['fp_filter'] = {
            'verdict': result.verdict,
            'confidence': result.confidence,
            'reason': result.reason,
            'rule_id': result.rule_id,
            'bounty_ceiling': result.bounty_ceiling,
        }
    return findings


# ── MASVS-aware post-filter ───────────────────────────────────────────────────

# Rules that CONFIRM a good security control is present — not a vulnerability.
# These get hard-killed to noise so they never waste LLM tokens.
POSITIVE_CONFIRMATION_RULES: frozenset = frozenset({
    'android_keystore_used',
    'android_important_for_autofill_no',
    'android_flag_secure_present',
    'android_obfuscation_enabled',
    'android_biometric_prompt_present',
    'android_rootbeer_present',
    'android_magisk_detection',
    'android_frida_detection_code',
    'android_play_integrity',
    'android_oauth_pkce_present',
    'android_xposed_detect',
    'android_safetynet_present',
    'android_native_string_decrypt',
})

# MASVS controls that were previously gaps — noise pre-filter must not kill these.
GAP_CONTROL_IDS: frozenset = frozenset({
    'AUTH-2', 'AUTH-3', 'PLATFORM-3',
    'RESILIENCE-3', 'PRIVACY-2', 'PRIVACY-3', 'PRIVACY-4', 'CODE-4',
})


def post_filter_masvs(finding: dict) -> dict:
    """
    Post-process a finding's fp_filter verdict using MASVS context.

    Call AFTER both filter_findings() and tag_findings_with_masvs() have run.

    Rules:
    - Positive confirmation rules → always noise (good control present, not a vuln)
    - Gap MASVS control findings wrongly killed as noise → upgrade to investigate
    """
    rule_id = finding.get('rule_id', '') or finding.get('title', '')
    fp = finding.get('fp_filter', {})

    if rule_id in POSITIVE_CONFIRMATION_RULES:
        fp['verdict'] = 'noise'
        fp['confidence'] = 95
        fp['reason'] = 'Positive confirmation of security control — not a vulnerability.'
        fp['bounty_ceiling'] = 0
        finding['fp_filter'] = fp
        return finding

    masvs_ids = set(finding.get('masvs_ids', []))
    if fp.get('verdict') == 'noise' and masvs_ids & GAP_CONTROL_IDS:
        fp['verdict'] = 'investigate'
        fp['confidence'] = max(fp.get('confidence', 85) - 30, 40)
        fp['reason'] = (fp.get('reason') or '') + ' BUT maps to a MASVS gap control — investigate.'
        fp['bounty_ceiling'] = max(fp.get('bounty_ceiling', 0), 30)
        finding['fp_filter'] = fp

    return finding
