#!/usr/bin/python
# coding=utf-8
"""Tests for new MASVS gap SAST rules and FP filter post-processor."""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Rule pattern correctness ──────────────────────────────────────────────────

RULE_PATTERNS = {
    'android_no_flag_secure': [
        r'class\s+(Login|Payment|Checkout|Password|Pin|Card|Account|Banking|Transfer)(Activity|Fragment)',
    ],
    'android_pii_in_log': [
        r'Log\.[vdiwef]\s*\(.*(?:email|ssn|dob|firstName|lastName|phoneNumber|creditCard|password|token)',
    ],
    'android_no_keystore_key_gen': [
        r'KeyGenerator\.getInstance\s*\(\s*"AES"\s*\)',
    ],
    'android_frida_gadget_strings': [
        r'frida-gadget|frida-agent|libfrida|frida_agent_main|gum_script_backend',
    ],
    'android_deprecated_http_client': [
        r'org\.apache\.http\.impl\.client\.DefaultHttpClient|org\.apache\.http\.client\.HttpClient',
    ],
    'android_clipboard_write': [
        r'setPrimaryClip|ClipData\.newPlainText',
    ],
    'android_no_biometric_before_sensitive': [
        r'(?:makePayment|initiateTransfer|deleteAccount|changePassword)\s*\(',
    ],
    'android_no_obfuscation_release': [
        r'minifyEnabled\s+false|minifyEnabled\s*=\s*false',
    ],
    'android_deprecated_telephony_imei': [
        r'getDeviceId\s*\(\s*\)|telephonyManager\.getDeviceId',
    ],
    'android_third_party_apk_install': [
        r'ACTION_INSTALL_PACKAGE|PackageInstaller\.Session|downloadApk|installApk',
    ],
}

SHOULD_MATCH = {
    'android_no_flag_secure':
        'class PaymentActivity extends AppCompatActivity {',
    'android_pii_in_log':
        'Log.d(TAG, "user email=" + email);',
    'android_no_keystore_key_gen':
        'KeyGenerator.getInstance("AES")',
    'android_frida_gadget_strings':
        'String s = "frida-gadget";',
    'android_deprecated_http_client':
        'new org.apache.http.impl.client.DefaultHttpClient()',
    'android_clipboard_write':
        'clipboard.setPrimaryClip(ClipData.newPlainText("", token));',
    'android_no_biometric_before_sensitive':
        'makePayment(amount, card);',
    'android_no_obfuscation_release':
        'minifyEnabled false',
    'android_deprecated_telephony_imei':
        'tm.getDeviceId()',
    'android_third_party_apk_install':
        'intent.setAction(Intent.ACTION_INSTALL_PACKAGE);',
}

SHOULD_NOT_MATCH = {
    'android_no_flag_secure':
        'class MainActivity extends AppCompatActivity {',
    'android_pii_in_log':
        'Log.d(TAG, "button clicked");',
    'android_frida_gadget_strings':
        'String s = "some_library";',
    'android_no_obfuscation_release':
        'minifyEnabled true',
    'android_no_biometric_before_sensitive':
        'makeToast("Payment done");',
}


@pytest.mark.parametrize('rule_id,code', list(SHOULD_MATCH.items()))
def test_rule_matches(rule_id, code):
    patterns = RULE_PATTERNS[rule_id]
    combined = '|'.join(f'(?:{p})' for p in patterns)
    assert re.search(combined, code, re.IGNORECASE), (
        f'Rule {rule_id} should match: {code!r}  pattern: {combined}'
    )


@pytest.mark.parametrize('rule_id,code', list(SHOULD_NOT_MATCH.items()))
def test_rule_no_false_positive(rule_id, code):
    patterns = RULE_PATTERNS[rule_id]
    combined = '|'.join(f'(?:{p})' for p in patterns)
    assert not re.search(combined, code, re.IGNORECASE), (
        f'Rule {rule_id} should NOT match: {code!r}'
    )


# ── YAML rule count sanity check ──────────────────────────────────────────────

def test_yaml_rule_count():
    import yaml
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_path = os.path.join(
        repo, 'mobsf', 'StaticAnalyzer', 'views', 'android', 'rules', 'android_rules.yaml'
    )
    data = yaml.safe_load(open(rules_path))
    assert isinstance(data, list), 'YAML should parse to a list'
    # We added ~25 new rules; total should now be > 80
    assert len(data) > 80, f'Expected >80 rules, got {len(data)}'
    new_rule_ids = {r['id'] for r in data}
    for expected_id in [
        'android_no_flag_secure', 'android_pii_in_log', 'android_keystore_used',
        'android_frida_gadget_strings', 'android_no_obfuscation_release',
        'android_clipboard_write', 'android_rootbeer_present',
    ]:
        assert expected_id in new_rule_ids, f'Rule {expected_id} missing from YAML'


# ── FP filter MASVS post-filter ───────────────────────────────────────────────

def test_positive_confirmation_becomes_noise():
    from mobsf.StaticAnalyzer.views.common.fp_filter import post_filter_masvs
    finding = {
        'rule_id': 'android_keystore_used',
        'title': 'KeyStore used',
        'description': 'AndroidKeyStore is used',
        'fp_filter': {
            'verdict': 'signal', 'confidence': 70,
            'reason': '', 'bounty_ceiling': 50,
        },
        'masvs_ids': ['CRYPTO-2'],
    }
    result = post_filter_masvs(finding)
    assert result['fp_filter']['verdict'] == 'noise'
    assert result['fp_filter']['bounty_ceiling'] == 0
    assert result['fp_filter']['confidence'] == 95


def test_gap_control_not_killed_by_noise_verdict():
    from mobsf.StaticAnalyzer.views.common.fp_filter import post_filter_masvs
    finding = {
        'rule_id': 'android_no_flag_secure',
        'title': 'No FLAG_SECURE',
        'description': 'Class PaymentActivity has no FLAG_SECURE',
        'fp_filter': {
            'verdict': 'noise', 'confidence': 85,
            'reason': 'Anti-debug pattern', 'bounty_ceiling': 0,
        },
        'masvs_ids': ['PLATFORM-8'],
    }
    result = post_filter_masvs(finding)
    assert result['fp_filter']['verdict'] == 'investigate'
    assert result['fp_filter']['bounty_ceiling'] >= 30
    assert 'MASVS gap control' in result['fp_filter']['reason']


def test_non_gap_noise_stays_noise():
    from mobsf.StaticAnalyzer.views.common.fp_filter import post_filter_masvs
    finding = {
        'rule_id': 'android_ip_disclosure',
        'title': 'IP Disclosure',
        'description': '192.168.1.1',
        'fp_filter': {
            'verdict': 'noise', 'confidence': 85,
            'reason': 'Private IP', 'bounty_ceiling': 5,
        },
        'masvs_ids': ['CODE-2'],
    }
    result = post_filter_masvs(finding)
    assert result['fp_filter']['verdict'] == 'noise'


def test_frida_gadget_classify_signal():
    from mobsf.StaticAnalyzer.views.common.fp_filter import classify_finding
    result = classify_finding(
        'frida-gadget found in native lib',
        'android_frida_gadget_strings',
        'lib/arm64-v8a/libapp.so',
        'frida-gadget',
    )
    assert result.verdict != 'noise', 'Frida gadget in a release binary should not be noise'


def test_frida_detection_code_is_noise_post_filter():
    from mobsf.StaticAnalyzer.views.common.fp_filter import post_filter_masvs
    finding = {
        'rule_id': 'android_frida_detection_code',
        'title': 'Frida detection code',
        'description': 'App detects Frida',
        'fp_filter': {
            'verdict': 'signal', 'confidence': 60,
            'reason': '', 'bounty_ceiling': 40,
        },
        'masvs_ids': ['RESILIENCE-4'],
    }
    result = post_filter_masvs(finding)
    # Detection code is a positive confirmation → noise
    assert result['fp_filter']['verdict'] == 'noise'
    assert result['fp_filter']['bounty_ceiling'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
