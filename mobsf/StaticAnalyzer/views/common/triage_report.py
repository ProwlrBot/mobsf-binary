#!/usr/bin/python
# coding=utf-8
"""
Triage report generator — produces a self-contained HTML report from
triaged MobSF findings. Designed for the Prowlr dark security aesthetic.

Usage:
    from mobsf.StaticAnalyzer.views.common.triage_report import generate_triage_report
    html = generate_triage_report(findings, app_info, llm_status)
    Path('triage.html').write_text(html)
"""
import html as _html
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── CSS ───────────────────────────────────────────────────────────────────────

CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#08090a;color:#e8e8e8;font-family:'Inter',system-ui,sans-serif;font-size:14px;line-height:1.5;min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:24px 16px}
.header{border-bottom:1px solid #1a1d20;padding-bottom:20px;margin-bottom:24px}
.header h1{font-size:22px;font-weight:700;letter-spacing:-0.3px;color:#e8e8e8}
.header h1 span{color:#e4f222}
.header-meta{color:#666;font-size:12px;font-family:'JetBrains Mono','Fira Code',monospace;margin-top:4px}
.llm-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:6px;margin-bottom:20px;font-size:12px;border:1px solid #1a1d20;background:#0f1012}
.llm-banner.active{border-color:#e4f222;color:#e4f222}
.llm-banner.inactive{color:#666}
.llm-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.llm-banner.active .llm-dot{background:#e4f222;box-shadow:0 0 6px #e4f222}
.llm-banner.inactive .llm-dot{background:#333}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:#0f1012;border:1px solid #1a1d20;border-radius:8px;padding:14px 16px}
.stat-card .stat-num{font-size:28px;font-weight:700;line-height:1;font-family:'JetBrains Mono','Fira Code',monospace}
.stat-card .stat-label{color:#666;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
.stat-p1 .stat-num{color:#ff4444}
.stat-p2 .stat-num{color:#ff8800}
.stat-p3 .stat-num{color:#e4f222}
.stat-noise .stat-num{color:#555}
.stat-total .stat-num{color:#e8e8e8}
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-box{flex:1;min-width:200px;background:#0f1012;border:1px solid #1a1d20;border-radius:6px;padding:8px 12px;color:#e8e8e8;font-size:13px;outline:none;transition:border-color 0.2s}
.search-box:focus{border-color:#e4f222}
.search-box::placeholder{color:#444}
.filter-btn{padding:7px 14px;border-radius:5px;border:1px solid #1a1d20;background:#0f1012;color:#666;font-size:12px;cursor:pointer;font-weight:600;letter-spacing:0.3px;transition:all 0.15s}
.filter-btn:hover,.filter-btn.active{background:#1a1d20;color:#e8e8e8}
.filter-btn.active.f-p1{border-color:#ff4444;color:#ff4444}
.filter-btn.active.f-p2{border-color:#ff8800;color:#ff8800}
.filter-btn.active.f-p3{border-color:#e4f222;color:#e4f222}
.filter-btn.active.f-noise{border-color:#555;color:#999}
.btn-export{margin-left:auto;padding:7px 14px;background:#e4f222;color:#08090a;border:none;border-radius:5px;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.3px}
.btn-export:hover{background:#f0f830}
.findings{display:flex;flex-direction:column;gap:10px}
.finding-card{background:#0f1012;border:1px solid #1a1d20;border-radius:8px;overflow:hidden;transition:border-color 0.15s}
.finding-card:hover{border-color:#2a2d30}
.finding-card.p1{border-left:3px solid #ff4444}
.finding-card.p2{border-left:3px solid #ff8800}
.finding-card.p3{border-left:3px solid #e4f222}
.finding-card.noise{border-left:3px solid #333;opacity:0.7}
.card-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.card-header:hover{background:rgba(255,255,255,0.02)}
.priority-badge{font-size:10px;font-weight:800;padding:3px 7px;border-radius:3px;letter-spacing:0.5px;flex-shrink:0;font-family:'JetBrains Mono',monospace}
.badge-p1{background:rgba(255,68,68,0.15);color:#ff4444;border:1px solid rgba(255,68,68,0.3)}
.badge-p2{background:rgba(255,136,0,0.15);color:#ff8800;border:1px solid rgba(255,136,0,0.3)}
.badge-p3{background:rgba(228,242,34,0.1);color:#e4f222;border:1px solid rgba(228,242,34,0.2)}
.badge-noise{background:rgba(255,255,255,0.03);color:#555;border:1px solid #222}
.score-pill{font-size:11px;font-family:'JetBrains Mono',monospace;color:#666;border:1px solid #1a1d20;border-radius:3px;padding:2px 6px}
.fp-pill{font-size:10px;padding:2px 6px;border-radius:3px;font-family:'JetBrains Mono',monospace}
.fp-high{background:rgba(255,68,68,0.08);color:#ff6666;border:1px solid rgba(255,68,68,0.15)}
.fp-medium{background:rgba(255,136,0,0.08);color:#ff9922;border:1px solid rgba(255,136,0,0.15)}
.fp-low{background:rgba(68,255,68,0.08);color:#44ff88;border:1px solid rgba(68,255,68,0.15)}
.card-title{flex:1;font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.expand-icon{color:#444;font-size:11px;flex-shrink:0;transition:transform 0.2s}
.card-body{padding:0 16px 14px;display:none}
.card-body.open{display:block}
.card-file{font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;color:#555;margin-bottom:10px;padding:6px 10px;background:#08090a;border-radius:4px;border:1px solid #1a1d20;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card-reasoning{font-size:12px;color:#aaa;margin-bottom:10px;line-height:1.6;padding:8px 10px;border-left:2px solid #1a1d20}
.card-chain{font-size:12px;color:#e4f222;margin-bottom:10px;padding:8px 10px;border-left:2px solid #e4f222;background:rgba(228,242,34,0.03);border-radius:0 4px 4px 0}
.action-block{position:relative}
.action-block pre{font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;background:#08090a;border:1px solid #1a1d20;border-radius:5px;padding:10px 36px 10px 12px;overflow-x:auto;color:#a8d8a8;white-space:pre-wrap;word-break:break-all;line-height:1.5}
.copy-btn{position:absolute;right:8px;top:8px;background:transparent;border:1px solid #2a2d30;border-radius:4px;padding:3px 7px;color:#555;font-size:10px;cursor:pointer;transition:all 0.15s}
.copy-btn:hover{border-color:#e4f222;color:#e4f222}
.copy-btn.copied{color:#44ff88;border-color:#44ff88}
.no-action{color:#333;font-size:11px;font-style:italic;padding:8px 10px;border:1px solid #1a1d20;border-radius:5px;background:#08090a}
.hidden{display:none!important}
.empty-state{text-align:center;padding:60px 20px;color:#333;font-size:14px}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #1a1d20;color:#333;font-size:11px;font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between}
@media print{
  body{background:#fff;color:#000}
  .finding-card{border:1px solid #ccc;page-break-inside:avoid}
  .toolbar,.btn-export,.copy-btn{display:none}
  .card-body{display:block!important}
  .finding-card.noise{display:none}
}
"""

# ── JS ────────────────────────────────────────────────────────────────────────

JS = r"""
(function(){
  var STORAGE_KEY='mobsf_triage_filters';
  var activeFilters=new Set(JSON.parse(localStorage.getItem(STORAGE_KEY)||'["P1","P2","P3","noise"]'));

  function saveFilters(){localStorage.setItem(STORAGE_KEY,JSON.stringify([...activeFilters]));}

  function applyFilters(){
    var q=(document.getElementById('search-box').value||'').toLowerCase();
    document.querySelectorAll('.finding-card').forEach(function(c){
      var pri=c.dataset.priority;
      var txt=c.textContent.toLowerCase();
      var matchFilter=activeFilters.has(pri);
      var matchSearch=!q||txt.includes(q);
      c.classList.toggle('hidden',!(matchFilter&&matchSearch));
    });
    var vis=document.querySelectorAll('.finding-card:not(.hidden)').length;
    document.getElementById('visible-count').textContent=vis+' findings';
  }

  document.querySelectorAll('.filter-btn[data-filter]').forEach(function(btn){
    var f=btn.dataset.filter;
    if(activeFilters.has(f))btn.classList.add('active');
    btn.addEventListener('click',function(){
      if(activeFilters.has(f)){activeFilters.delete(f);btn.classList.remove('active');}
      else{activeFilters.add(f);btn.classList.add('active');}
      saveFilters();applyFilters();
    });
  });

  document.getElementById('search-box').addEventListener('input',applyFilters);

  document.querySelectorAll('.card-header').forEach(function(h){
    h.addEventListener('click',function(){
      var body=h.nextElementSibling;
      var icon=h.querySelector('.expand-icon');
      body.classList.toggle('open');
      icon.textContent=body.classList.contains('open')?'▲':'▼';
    });
  });

  document.querySelectorAll('.copy-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var pre=btn.previousElementSibling;
      navigator.clipboard.writeText(pre.textContent).then(function(){
        btn.textContent='✓';btn.classList.add('copied');
        setTimeout(function(){btn.textContent='copy';btn.classList.remove('copied');},1500);
      });
    });
  });

  document.getElementById('btn-export').addEventListener('click',function(){
    var lines=['# MobSF Triage Export\n'];
    document.querySelectorAll('.finding-card.p1,.finding-card.p2').forEach(function(c){
      var title=c.querySelector('.card-title').textContent;
      var pri=c.dataset.priority;
      var score=c.dataset.score;
      var reasoning=c.querySelector('.card-reasoning');
      var action=c.querySelector('.action-block pre');
      lines.push('## ['+pri+'] '+title);
      lines.push('**Bounty score:** '+score+'/100');
      if(reasoning)lines.push('**Analysis:** '+reasoning.textContent.trim());
      if(action)lines.push('```\n'+action.textContent.trim()+'\n```');
      lines.push('');
    });
    navigator.clipboard.writeText(lines.join('\n'));
    var btn=document.getElementById('btn-export');
    btn.textContent='✓ Copied';
    setTimeout(function(){btn.textContent='Export P1+P2';},2000);
  });

  applyFilters();
})();
"""

# ── HTML generation ────────────────────────────────────────────────────────────

PRIORITY_ORDER = {'P1': 0, 'P2': 1, 'P3': 2, 'noise': 3}


def _e(text: str) -> str:
    return _html.escape(str(text), quote=True)


def _priority_badge(priority: str) -> str:
    cls = {'P1': 'badge-p1', 'P2': 'badge-p2', 'P3': 'badge-p3'}.get(priority, 'badge-noise')
    return f'<span class="priority-badge {cls}">{_e(priority)}</span>'


def _fp_pill(fp_risk: str) -> str:
    cls = {'low': 'fp-low', 'medium': 'fp-medium', 'high': 'fp-high'}.get(fp_risk, 'fp-medium')
    return f'<span class="fp-pill {cls}">FP:{_e(fp_risk)}</span>'


def _normalize_priority(finding: dict) -> str:
    triage = finding.get('triage', {})
    fp_filter = finding.get('fp_filter', {})
    priority = triage.get('priority') or fp_filter.get('verdict', 'noise')
    remap = {'investigate': 'P3', 'signal': 'P2', 'likely_fp': 'noise'}
    priority = remap.get(priority, priority)
    if triage.get('bounty_score', 0) < 10 and priority not in ('P1', 'P2'):
        priority = 'noise'
    return priority if priority in ('P1', 'P2', 'P3', 'noise') else 'noise'


def _finding_card(finding: dict) -> str:
    triage = finding.get('triage', {})
    fp_filter = finding.get('fp_filter', {})
    priority = _normalize_priority(finding)
    score = triage.get('bounty_score', fp_filter.get('bounty_ceiling', 0))
    fp_risk = triage.get('fp_risk', 'high')
    title = finding.get('title', '') or finding.get('rule_id', 'Finding')
    file_path = finding.get('file_path', '') or finding.get('file', '')
    reasoning = triage.get('reasoning', '') or fp_filter.get('reason', '')
    next_action = triage.get('next_action', '')
    chain = triage.get('exploitation_path', '')

    if next_action:
        action_html = (
            f'<div class="action-block">'
            f'<pre>{_e(next_action)}</pre>'
            f'<button class="copy-btn">copy</button>'
            f'</div>'
        )
    else:
        action_html = '<div class="no-action">— next action not generated (no LLM or noise finding) —</div>'

    chain_html = f'<div class="card-chain">&#9889; {_e(chain)}</div>' if chain else ''

    return (
        f'<div class="finding-card {priority.lower()}" '
        f'data-priority="{_e(priority)}" data-score="{_e(str(score))}">'
        f'<div class="card-header">'
        f'{_priority_badge(priority)}'
        f'<span class="score-pill">{_e(str(score))}/100</span>'
        f'{_fp_pill(fp_risk)}'
        f'<span class="card-title">{_e(title)}</span>'
        f'<span class="expand-icon">&#9660;</span>'
        f'</div>'
        f'<div class="card-body">'
        f'<div class="card-file">{_e(file_path or "—")}</div>'
        f'<div class="card-reasoning">{_e(reasoning)}</div>'
        f'{chain_html}'
        f'{action_html}'
        f'</div>'
        f'</div>'
    )


def generate_triage_report(
    findings: list,
    app_info: dict | None = None,
    llm_status: dict | None = None,
) -> str:
    """
    Generate a self-contained HTML triage report.

    Args:
        findings:   list of finding dicts with optional triage + fp_filter keys
        app_info:   {"app_name": str, "package": str, "version": str, "platform": str}
        llm_status: from llm_triage.get_provider_status()

    Returns:
        Complete HTML string.
    """
    app = app_info or {}
    llm = llm_status or {}
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    findings = sorted(
        findings,
        key=lambda f: (
            PRIORITY_ORDER.get(_normalize_priority(f), 3),
            -f.get('triage', {}).get('bounty_score', 0),
        ),
    )

    counts: dict[str, int] = {'P1': 0, 'P2': 0, 'P3': 0, 'noise': 0}
    top_score = 0
    for f in findings:
        p = _normalize_priority(f)
        counts[p] += 1
        s = f.get('triage', {}).get('bounty_score', 0)
        if s > top_score:
            top_score = s
    total = len(findings)

    llm_active = llm.get('available', False) and llm.get('provider', 'none') != 'none'
    llm_text = (
        f"LLM active: {llm.get('provider', '?')} / {llm.get('model', '?')}"
        if llm_active
        else 'LLM offline — using rule-based scoring. Set MOBSF_LLM_PROVIDER to enable.'
    )
    llm_cls = 'active' if llm_active else 'inactive'
    llm_banner = (
        f'<div class="llm-banner {llm_cls}">'
        f'<div class="llm-dot"></div>'
        f'<span>{_e(llm_text)}</span>'
        f'</div>'
    )

    stats_html = (
        f'<div class="stats">'
        f'<div class="stat-card stat-total"><div class="stat-num">{total}</div><div class="stat-label">Total</div></div>'
        f'<div class="stat-card stat-p1"><div class="stat-num">{counts["P1"]}</div><div class="stat-label">P1</div></div>'
        f'<div class="stat-card stat-p2"><div class="stat-num">{counts["P2"]}</div><div class="stat-label">P2</div></div>'
        f'<div class="stat-card stat-p3"><div class="stat-num">{counts["P3"]}</div><div class="stat-label">P3</div></div>'
        f'<div class="stat-card stat-noise"><div class="stat-num">{counts["noise"]}</div><div class="stat-label">Noise</div></div>'
        f'<div class="stat-card"><div class="stat-num" style="color:#e4f222">{top_score}</div><div class="stat-label">Top Score</div></div>'
        f'</div>'
    )

    cards_html = '\n'.join(_finding_card(f) for f in findings)
    if not cards_html:
        cards_html = '<div class="empty-state">No findings to display.</div>'

    app_name = app.get('app_name', 'Unknown App')
    platform = app.get('platform', 'android').upper()
    version = app.get('version', '')
    pkg = app.get('package', '')

    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'<title>Triage — {_e(app_name)}</title>\n'
        f'<style>{CSS}</style>\n'
        '</head>\n'
        '<body>\n'
        '<div class="container">\n'
        f'<div class="header"><h1>Prowlr <span>Triage</span> — {_e(app_name)}</h1>'
        f'<div class="header-meta">{_e(platform)} · {_e(pkg)} · v{_e(version)} · {_e(now)}</div></div>\n'
        f'{llm_banner}\n'
        f'{stats_html}\n'
        '<div class="toolbar">\n'
        '<input id="search-box" class="search-box" type="text" placeholder="Search findings…">\n'
        '<button class="filter-btn f-p1" data-filter="P1">P1</button>\n'
        '<button class="filter-btn f-p2" data-filter="P2">P2</button>\n'
        '<button class="filter-btn f-p3" data-filter="P3">P3</button>\n'
        '<button class="filter-btn f-noise" data-filter="noise">Noise</button>\n'
        '<span id="visible-count" style="color:#555;font-size:11px;font-family:monospace"></span>\n'
        '<button class="btn-export" id="btn-export">Export P1+P2</button>\n'
        '</div>\n'
        f'<div class="findings">\n{cards_html}\n</div>\n'
        f'<div class="footer"><span>ProwlrBot / mobsf-binary</span><span>{_e(now)}</span></div>\n'
        '</div>\n'
        f'<script>{JS}</script>\n'
        '</body>\n'
        '</html>'
    )
