#!/usr/bin/python
# coding=utf-8
"""
JWT (JSON Web Token) security analysis for mobile apps.

Finds JWT tokens embedded in source code or binary strings, decodes them,
and audits for common security issues:
  - alg:none — unsigned tokens accepted
  - RS256 -> HS256 algorithm confusion attack
  - Missing or already-expired exp claim
  - Overly long expiry (> 90 days)
  - Sensitive data in payload (PII, passwords, internal IDs)
"""
import base64
import json
import logging
import re
import time

logger = logging.getLogger(__name__)

JWT_REGEX = re.compile(
    r'eyJ[A-Za-z0-9_-]+'        # header (always starts with eyJ)
    r'\.'
    r'eyJ[A-Za-z0-9_-]*'        # payload (starts with eyJ for JSON objects)
    r'(?:\.[A-Za-z0-9_-]*)?',   # signature (optional — absent for alg:none)
    re.ASCII,
)

SENSITIVE_PAYLOAD_KEYS = {
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'ssn', 'social_security', 'credit_card', 'cc_number', 'cvv',
    'private_key', 'private', 'credentials',
}

MAX_REFRESH_TOKEN_EXPIRY = 86400 * 90  # 90 days in seconds


def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding."""
    s = s.replace('-', '+').replace('_', '/')
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.b64decode(s)


def _decode_jwt(token: str) -> tuple[dict | None, dict | None, str]:
    """
    Decode a JWT without verification.
    Returns (header, payload, error_msg).
    """
    parts = token.split('.')
    if len(parts) < 2:
        return None, None, 'invalid structure'
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, ''
    except Exception as e:
        return None, None, str(e)


def _audit_jwt(token: str, header: dict, payload: dict) -> list[dict]:
    """Return a list of security findings for a decoded JWT."""
    issues = []
    alg = header.get('alg', '').lower()

    if alg == 'none':
        issues.append({
            'issue': 'Algorithm "none" — token accepts no signature',
            'detail': (
                'The JWT header sets alg=none, meaning the server may accept this '
                'token without any cryptographic verification. An attacker can '
                'forge arbitrary claims by stripping the signature.'
            ),
            'severity': 'high',
            'cvss': 9.1,
            'cwe': 'CWE-347',
            'masvs': 'AUTH-1',
        })

    if alg in ('hs256', 'hs384', 'hs512'):
        if any(k in payload for k in ('sub', 'iss', 'aud', 'email', 'userId', 'user_id')):
            issues.append({
                'issue': f'HMAC algorithm ({alg.upper()}) — potential RS256->HS256 confusion',
                'detail': (
                    f'Token uses {alg.upper()} (symmetric HMAC). If the server also '
                    'accepts RS256 tokens, an attacker can sign a token with the '
                    "server's public key (used as the HMAC secret) to impersonate "
                    'any user. Verify the server enforces algorithm binding.'
                ),
                'severity': 'warning',
                'cvss': 7.5,
                'cwe': 'CWE-347',
                'masvs': 'AUTH-1',
            })

    exp = payload.get('exp')
    if exp is None:
        issues.append({
            'issue': 'Missing exp claim — token never expires',
            'detail': (
                'The JWT payload has no exp (expiration) claim. Without expiry, '
                'a stolen token grants permanent access with no revocation path.'
            ),
            'severity': 'warning',
            'cvss': 6.5,
            'cwe': 'CWE-613',
            'masvs': 'AUTH-1',
        })
    elif isinstance(exp, (int, float)):
        now = time.time()
        if exp < now:
            issues.append({
                'issue': 'Token already expired — likely hardcoded test token',
                'detail': (
                    f'The exp claim ({int(exp)}) is in the past. This is '
                    'almost certainly a hardcoded token from development or testing. '
                    'Hardcoded tokens are a credential leak even if currently expired.'
                ),
                'severity': 'warning',
                'cvss': 5.3,
                'cwe': 'CWE-798',
                'masvs': 'STORAGE-1',
            })
        iat = payload.get('iat', now)
        lifetime = exp - (iat if isinstance(iat, (int, float)) else now)
        if lifetime > MAX_REFRESH_TOKEN_EXPIRY:
            issues.append({
                'issue': f'Extremely long-lived token ({int(lifetime / 86400)} day lifetime)',
                'detail': (
                    f'Token lifetime of {int(lifetime / 86400)} days exceeds the 90-day '
                    'maximum recommended for refresh tokens. Access tokens should expire '
                    'in minutes to hours, not months.'
                ),
                'severity': 'warning',
                'cvss': 4.3,
                'cwe': 'CWE-613',
                'masvs': 'AUTH-1',
            })

    sensitive_found = [k for k in payload if k.lower() in SENSITIVE_PAYLOAD_KEYS]
    if sensitive_found:
        issues.append({
            'issue': f'Sensitive fields in JWT payload: {", ".join(sensitive_found)}',
            'detail': (
                'JWT payloads are base64-encoded, not encrypted. Any party with '
                f'the token can read these fields: {", ".join(sensitive_found)}. '
                'Never store passwords, secrets, or unencrypted credentials in a JWT.'
            ),
            'severity': 'high',
            'cvss': 7.5,
            'cwe': 'CWE-312',
            'masvs': 'STORAGE-1',
        })

    if alg in ('rs1', 'hs1', 'md5'):
        issues.append({
            'issue': f'Cryptographically weak JWT algorithm: {alg.upper()}',
            'detail': (
                f'Algorithm {alg.upper()} is cryptographically broken. '
                'Use RS256, ES256, or PS256 for asymmetric tokens, or HS256+ for symmetric.'
            ),
            'severity': 'high',
            'cvss': 8.1,
            'cwe': 'CWE-327',
            'masvs': 'CRYPTO-1',
        })

    return issues


def find_jwts_in_strings(strings: list[str]) -> list[dict]:
    """
    Search a list of strings for JWT tokens and audit each one.
    Returns a list of token analysis dicts.
    """
    seen: set[str] = set()
    results = []
    for s in strings:
        if not isinstance(s, str):
            continue
        for match in JWT_REGEX.finditer(s):
            token = match.group(0)
            if token in seen or len(token) < 20:
                continue
            seen.add(token)
            header, payload, err = _decode_jwt(token)
            if err or header is None:
                continue
            issues = _audit_jwt(token, header, payload)
            results.append({
                'token_preview': token[:40] + '...',
                'header': header,
                'payload': {k: v for k, v in payload.items() if k not in SENSITIVE_PAYLOAD_KEYS},
                'issues': issues,
                'has_issues': bool(issues),
                'alg': header.get('alg', 'unknown'),
                'typ': header.get('typ', 'JWT'),
            })
    return results


def analyze_jwts(strings: list[str]) -> dict:
    """
    Top-level JWT analysis entry point for MobSF pipeline integration.

    Args:
        strings: list of strings from binary/source extraction

    Returns:
        {
            "tokens_found": int,
            "tokens_with_issues": int,
            "findings": [<token dicts that have issues>],
            "all_tokens": [<all decoded tokens>],
            "severity": "high" | "warning" | "info",
        }
    """
    all_tokens = find_jwts_in_strings(strings)
    tokens_with_issues = [t for t in all_tokens if t['has_issues']]
    all_issues = [i for t in tokens_with_issues for i in t['issues']]

    overall = 'info'
    for issue in all_issues:
        if issue['severity'] == 'high':
            overall = 'high'
            break
        if issue['severity'] == 'warning':
            overall = 'warning'

    return {
        'tokens_found': len(all_tokens),
        'tokens_with_issues': len(tokens_with_issues),
        'findings': tokens_with_issues,
        'all_tokens': all_tokens,
        'severity': overall,
    }
