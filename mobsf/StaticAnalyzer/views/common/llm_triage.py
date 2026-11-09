#!/usr/bin/python
# coding=utf-8
"""
LLM-powered finding triage for MobSF.

Scores each finding for bounty-worthiness, false-positive risk, and
generates the next decisive test command — so the analyst spends time
on signal, not noise.

Supported providers (all OpenAI-compatible unless noted):
  lmstudio   — LM Studio local server (default: http://localhost:1234/v1)
  ollama     — Ollama local server    (default: http://localhost:11434/v1)
  openai     — OpenAI API
  anthropic  — Anthropic API (native SDK)
  none       — disable LLM, use rule-based scoring only

Configuration (env vars, highest priority wins):
  MOBSF_LLM_PROVIDER   lmstudio | ollama | openai | anthropic | none
  MOBSF_LLM_BASE_URL   override base URL (e.g. http://10.0.0.5:1234/v1)
  MOBSF_LLM_MODEL      model name (e.g. hermes3, gpt-4o-mini, claude-haiku-4-5)
  MOBSF_LLM_API_KEY    API key (not needed for LM Studio / Ollama)
  MOBSF_LLM_TIMEOUT    request timeout in seconds (default: 30)
"""
import json
import logging
import os
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Defaults per provider ─────────────────────────────────────────────────────

PROVIDER_DEFAULTS = {
    'lmstudio':  {'base_url': 'http://localhost:1234/v1',   'model': 'local-model', 'key': 'lm-studio'},
    'ollama':    {'base_url': 'http://localhost:11434/v1',  'model': 'hermes3',     'key': 'ollama'},
    'openai':    {'base_url': 'https://api.openai.com/v1',  'model': 'gpt-4o-mini', 'key': ''},
    'anthropic': {'base_url': 'https://api.anthropic.com',  'model': 'claude-haiku-4-5', 'key': ''},
}

# ── Config loading ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load LLM config: env vars > ~/.config/mobsf/llm.json > defaults."""
    cfg = {'provider': 'auto', 'base_url': '', 'model': '', 'api_key': '', 'timeout': 30}
    cfg_path = Path.home() / '.config' / 'mobsf' / 'llm.json'
    if cfg_path.exists():
        try:
            file_cfg = json.loads(cfg_path.read_text())
            cfg.update(file_cfg)
        except Exception:
            pass
    if os.environ.get('MOBSF_LLM_PROVIDER'):
        cfg['provider'] = os.environ['MOBSF_LLM_PROVIDER'].lower()
    if os.environ.get('MOBSF_LLM_BASE_URL'):
        cfg['base_url'] = os.environ['MOBSF_LLM_BASE_URL']
    if os.environ.get('MOBSF_LLM_MODEL'):
        cfg['model'] = os.environ['MOBSF_LLM_MODEL']
    if os.environ.get('MOBSF_LLM_API_KEY'):
        cfg['api_key'] = os.environ['MOBSF_LLM_API_KEY']
    if os.environ.get('MOBSF_LLM_TIMEOUT'):
        try:
            cfg['timeout'] = int(os.environ['MOBSF_LLM_TIMEOUT'])
        except ValueError:
            pass
    return cfg


def _auto_detect_provider() -> str:
    """Probe local providers. Returns first reachable one."""
    for name, defaults in [('lmstudio', PROVIDER_DEFAULTS['lmstudio']),
                            ('ollama',   PROVIDER_DEFAULTS['ollama'])]:
        try:
            req = urllib.request.Request(
                defaults['base_url'] + '/models',
                headers={'Authorization': f"Bearer {defaults['key']}"},
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                if r.status == 200:
                    logger.info('Auto-detected LLM provider: %s', name)
                    return name
        except Exception:
            pass
    return 'none'


# ── Triage prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior mobile security researcher and bug bounty analyst.
Your job is to triage MobSF static analysis findings and determine which are
worth investigating vs noise. Be ruthlessly honest — most findings are FPs.

Respond ONLY with valid JSON matching this schema (no markdown, no explanation):
{
  "bounty_score": <int 0-100>,
  "fp_risk": <"low"|"medium"|"high">,
  "priority": <"P1"|"P2"|"P3"|"noise">,
  "reasoning": "<1-2 sentences max>",
  "next_action": "<exact shell command or adb command to validate this finding>",
  "exploitation_path": "<if real: 1 sentence attack chain, else empty string>"
}

Scoring guide:
  P1 / bounty_score 70-100: Direct auth bypass, RCE, account takeover, payment tampering
  P2 / bounty_score 40-70:  Information disclosure, SSRF, stored XSS, privilege escalation
  P3 / bounty_score 10-40:  Low-severity logic issues, weak crypto in non-critical path
  noise / bounty_score 0-10: Anti-debug, missing headers, generic logging, public API keys

fp_risk: high = very likely FP (e.g. google_api_key with no exploitable service)
         medium = may be real but needs confirmation
         low = strong evidence of real issue
"""

USER_PROMPT_TEMPLATE = """\
App: {app_name} ({package})
Target SDK: {target_sdk}
Finding title: {title}
Finding description: {description}
File: {file_path}
Code snippet:
{code_snippet}
Pre-filter verdict: {prefilter_verdict} (rule: {prefilter_rule})
"""


# ── OpenAI-compatible chat completion ─────────────────────────────────────────

def _openai_chat(
    base_url: str,
    api_key: str,
    model: str,
    messages: list,
    timeout: int = 30,
) -> str:
    """Call an OpenAI-compatible chat completion endpoint. Returns response text."""
    payload = json.dumps({
        'model': model,
        'messages': messages,
        'temperature': 0.1,
        'max_tokens': 300,
        'response_format': {'type': 'json_object'},
    }).encode()
    req = urllib.request.Request(
        f'{base_url.rstrip("/")}/chat/completions',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key or "none"}',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data['choices'][0]['message']['content']


def _anthropic_chat(
    api_key: str,
    model: str,
    system: str,
    user_msg: str,
    timeout: int = 30,
) -> str:
    """Call Anthropic Messages API. Returns response text."""
    payload = json.dumps({
        'model': model,
        'max_tokens': 300,
        'system': system,
        'messages': [{'role': 'user', 'content': user_msg}],
    }).encode()
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data['content'][0]['text']


# ── Triage result ──────────────────────────────────────────────────────────────

@dataclass
class TriageResult:
    bounty_score: int = 0
    fp_risk: str = 'high'
    priority: str = 'noise'
    reasoning: str = ''
    next_action: str = ''
    exploitation_path: str = ''
    provider_used: str = 'none'
    error: str = ''


def _rule_based_score(prefilter_verdict: str, bounty_ceiling: int) -> TriageResult:
    """Fallback rule-based scoring when no LLM is available."""
    score_map = {'noise': 0, 'likely_fp': 10, 'investigate': 35, 'signal': 65}
    priority_map = {'noise': 'noise', 'likely_fp': 'P3', 'investigate': 'P2', 'signal': 'P2'}
    fp_map = {'noise': 'high', 'likely_fp': 'high', 'investigate': 'medium', 'signal': 'low'}
    base_score = score_map.get(prefilter_verdict, 20)
    score = min(base_score, bounty_ceiling)
    return TriageResult(
        bounty_score=score,
        fp_risk=fp_map.get(prefilter_verdict, 'medium'),
        priority=priority_map.get(prefilter_verdict, 'P3'),
        reasoning='Rule-based scoring (no LLM configured).',
        next_action='',
        provider_used='rules',
    )


_config = None


def _get_config() -> dict:
    global _config
    if _config is None:
        _config = _load_config()
        if _config['provider'] == 'auto':
            _config['provider'] = _auto_detect_provider()
        defaults = PROVIDER_DEFAULTS.get(_config['provider'], {})
        if not _config['base_url'] and defaults.get('base_url'):
            _config['base_url'] = defaults['base_url']
        if not _config['model'] and defaults.get('model'):
            _config['model'] = defaults['model']
        if not _config['api_key'] and defaults.get('key'):
            _config['api_key'] = defaults['key']
    return _config


def triage_finding(
    finding: dict,
    app_context: dict = None,
) -> TriageResult:
    """
    Triage a single MobSF finding using LLM + rule-based fallback.

    Args:
        finding: dict with keys: title, description, file_path, code, fp_filter
        app_context: dict with keys: app_name, package, target_sdk

    Returns:
        TriageResult with bounty_score, fp_risk, priority, next_action
    """
    cfg = _get_config()
    prefilter = finding.get('fp_filter', {})
    prefilter_verdict = prefilter.get('verdict', 'investigate')
    bounty_ceiling = prefilter.get('bounty_ceiling', 50)

    # Skip LLM for confirmed noise (save tokens)
    if prefilter_verdict == 'noise' and prefilter.get('confidence', 0) >= 80:
        result = _rule_based_score(prefilter_verdict, bounty_ceiling)
        result.reasoning = prefilter.get('reason', 'Rule-matched noise pattern.')
        return result

    if cfg['provider'] == 'none':
        return _rule_based_score(prefilter_verdict, bounty_ceiling)

    ctx = app_context or {}
    user_msg = USER_PROMPT_TEMPLATE.format(
        app_name=ctx.get('app_name', 'unknown'),
        package=ctx.get('package', 'unknown'),
        target_sdk=ctx.get('target_sdk', 'unknown'),
        title=finding.get('title', ''),
        description=(finding.get('description', '') or finding.get('message', ''))[:500],
        file_path=finding.get('file_path', '') or finding.get('file', ''),
        code_snippet=(finding.get('code', '') or finding.get('snippet', ''))[:300],
        prefilter_verdict=prefilter_verdict,
        prefilter_rule=prefilter.get('rule_id', ''),
    )

    try:
        if cfg['provider'] == 'anthropic':
            raw = _anthropic_chat(
                cfg['api_key'], cfg['model'], SYSTEM_PROMPT, user_msg, cfg['timeout'])
        else:
            raw = _openai_chat(
                cfg['base_url'], cfg['api_key'], cfg['model'],
                [{'role': 'system', 'content': SYSTEM_PROMPT},
                 {'role': 'user', 'content': user_msg}],
                cfg['timeout'],
            )
        parsed = json.loads(raw)
        return TriageResult(
            bounty_score=min(int(parsed.get('bounty_score', 0)), bounty_ceiling),
            fp_risk=parsed.get('fp_risk', 'medium'),
            priority=parsed.get('priority', 'P3'),
            reasoning=parsed.get('reasoning', ''),
            next_action=parsed.get('next_action', ''),
            exploitation_path=parsed.get('exploitation_path', ''),
            provider_used=cfg['provider'],
        )
    except Exception as e:
        logger.warning('LLM triage failed (%s): %s', cfg['provider'], e)
        return _rule_based_score(prefilter_verdict, bounty_ceiling)


def triage_all_findings(
    findings: list,
    app_context: dict = None,
    skip_noise: bool = True,
) -> list:
    """
    Triage all findings in a MobSF scan result.
    Adds a 'triage' key to each finding dict with the TriageResult fields.
    Returns findings sorted by bounty_score descending.
    """
    for finding in findings:
        result = triage_finding(finding, app_context)
        finding['triage'] = {
            'bounty_score': result.bounty_score,
            'fp_risk': result.fp_risk,
            'priority': result.priority,
            'reasoning': result.reasoning,
            'next_action': result.next_action,
            'exploitation_path': result.exploitation_path,
            'provider': result.provider_used,
        }
    if skip_noise:
        findings.sort(
            key=lambda f: (
                f.get('triage', {}).get('priority', 'noise') == 'noise',
                -f.get('triage', {}).get('bounty_score', 0),
            )
        )
    return findings


def get_provider_status() -> dict:
    """Return current LLM provider config status (safe to expose in UI)."""
    cfg = _get_config()
    return {
        'provider': cfg['provider'],
        'model': cfg['model'],
        'base_url': cfg['base_url'],
        'api_key_set': bool(cfg.get('api_key')),
        'available': cfg['provider'] != 'none',
        'config_file': str(Path.home() / '.config' / 'mobsf' / 'llm.json'),
    }
