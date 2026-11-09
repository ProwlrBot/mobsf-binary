#!/usr/bin/python
# coding=utf-8
"""
Top-level triage pipeline for MobSF findings.

Orchestrates the full triage pass:
  1. fp_filter   — rule-based noise elimination
  2. llm_triage  — LLM scoring (bounty_score, fp_risk, priority, next_action)
  3. masvs       — tag findings with MASVS v2.1 control IDs
  4. report      — generate HTML triage report

Usage:
    from mobsf.StaticAnalyzer.views.common.triage_pipeline import run_triage
    result = run_triage(findings, app_info)
    # result['html'] — HTML triage report
    # result['findings'] — enriched findings list
    # result['coverage'] — MASVS v2.1 coverage report
    # result['stats'] — P1/P2/P3/noise counts, top score
"""
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def run_triage(
    findings: list[dict],
    app_info: dict | None = None,
    skip_llm: bool = False,
    skip_noise_in_report: bool = False,
) -> dict[str, Any]:
    """
    Run the full triage pipeline on a list of MobSF findings.

    Args:
        findings:            list of MobSF finding dicts
        app_info:            {"app_name", "package", "version", "platform"}
        skip_llm:            force rule-based scoring even if LLM is configured
        skip_noise_in_report: omit noise findings from the HTML report

    Returns:
        {
            "findings":  enriched findings (fp_filter + triage + masvs_ids),
            "coverage":  MASVS v2.1 coverage report dict,
            "html":      self-contained HTML triage report string,
            "stats":     {total, p1, p2, p3, noise, top_score},
            "llm_status": LLM provider status dict,
        }
    """
    # -- Step 1: FP filter
    try:
        from mobsf.StaticAnalyzer.views.common.fp_filter import filter_findings
        findings = filter_findings(findings)
    except Exception:
        logger.exception('fp_filter failed — continuing without pre-filter')

    # -- Step 2: LLM triage
    llm_status: dict = {'provider': 'none', 'available': False}
    try:
        from mobsf.StaticAnalyzer.views.common.llm_triage import (
            triage_all_findings, get_provider_status,
        )
        if skip_llm:
            os.environ.setdefault('MOBSF_LLM_PROVIDER', 'none')
        findings = triage_all_findings(findings, app_context=app_info, skip_noise=False)
        llm_status = get_provider_status()
    except Exception:
        logger.exception('llm_triage failed — continuing with rule-based scores')

    # -- Step 3: MASVS tagging
    coverage: dict = {}
    try:
        from mobsf.StaticAnalyzer.views.common.masvs_coverage import (
            tag_findings_with_masvs, coverage_report,
        )
        findings = tag_findings_with_masvs(findings)
        coverage = coverage_report(findings)
    except Exception:
        logger.exception('masvs_coverage failed — continuing without MASVS tags')

    # -- Step 4: Stats
    counts = {'P1': 0, 'P2': 0, 'P3': 0, 'noise': 0}
    top_score = 0
    for f in findings:
        p = f.get('triage', {}).get('priority', 'noise')
        counts[p if p in counts else 'noise'] += 1
        s = f.get('triage', {}).get('bounty_score', 0)
        if s > top_score:
            top_score = s
    stats = {
        'total': len(findings),
        'p1': counts['P1'],
        'p2': counts['P2'],
        'p3': counts['P3'],
        'noise': counts['noise'],
        'top_score': top_score,
    }

    # -- Step 5: HTML report
    html = ''
    try:
        from mobsf.StaticAnalyzer.views.common.triage_report import generate_triage_report
        report_findings = findings
        if skip_noise_in_report:
            report_findings = [
                f for f in findings
                if f.get('triage', {}).get('priority', 'noise') != 'noise'
            ]
        html = generate_triage_report(report_findings, app_info, llm_status)
    except Exception:
        logger.exception('triage_report failed — HTML not generated')

    return {
        'findings': findings,
        'coverage': coverage,
        'html': html,
        'stats': stats,
        'llm_status': llm_status,
    }
