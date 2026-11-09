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

/* header */
.header{border-bottom:1px solid #1a1d20;padding-bottom:20px;margin-bottom:24px}
.header h1{font-size:22px;font-weight:700;letter-spacing:-0.3px;color:#e8e8e8}
.header h1 span{color:#e4f222}
.header-meta{color:#666;font-size:12px;font-family:'JetBrains Mono','Fira Code',monospace;margin-top:4px}

/* llm banner */
.llm-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:6px;margin-bottom:20px;font-size:12px;border:1px solid #1a1d20;background:#0f1012;flex-wrap:wrap}
.llm-banner.active{border-color:#e4f222;color:#e4f222}
.llm-banner.inactive{color:#666}
.llm-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.llm-banner.active .llm-dot{background:#e4f222;box-shadow:0 0 6px #e4f222}
.llm-banner.inactive .llm-dot{background:#333}
.llm-batch{margin-left:auto;font-size:11px;opacity:0.7}

/* stats row */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:16px}
.stat-card{background:#0f1012;border:1px solid #1a1d20;border-radius:8px;padding:14px 16px}
.stat-card .stat-num{font-size:26px;font-weight:700;line-height:1;font-family:'JetBrains Mono','Fira Code',monospace}
.stat-card .stat-label{color:#666;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}
.stat-p1 .stat-num{color:#ff4444}
.stat-p2 .stat-num{color:#ff8800}
.stat-p3 .stat-num{color:#e4f222}
.stat-noise .stat-num{color:#555}
.stat-total .stat-num{color:#e8e8e8}

/* progress bar */
.progress-row{margin-bottom:20px;background:#0f1012;border:1px solid #1a1d20;border-radius:8px;padding:12px 16px}
.progress-label{font-size:11px;color:#666;margin-bottom:6px;display:flex;justify-content:space-between}
.progress-track{height:4px;background:#1a1d20;border-radius:2px;overflow:hidden;position:relative}
.progress-fill{height:100%;background:#e4f222;border-radius:2px;transition:width 0.3s}
.progress-counts{display:flex;gap:16px;margin-top:8px;flex-wrap:wrap}
.prog-pill{font-size:11px;font-family:'JetBrains Mono',monospace}
.prog-proven{color:#44ff88}
.prog-reported{color:#e4f222}
.prog-investigating{color:#ff8800}
.prog-disproven{color:#ff4444}

/* toolbar */
.toolbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-box{flex:1;min-width:180px;background:#0f1012;border:1px solid #1a1d20;border-radius:6px;padding:7px 12px;color:#e8e8e8;font-size:13px;outline:none;transition:border-color 0.2s}
.search-box:focus{border-color:#e4f222}
.search-box::placeholder{color:#444}
.filter-select{padding:7px 10px;border-radius:5px;border:1px solid #1a1d20;background:#0f1012;color:#888;font-size:12px;cursor:pointer;outline:none;appearance:none;-webkit-appearance:none;padding-right:24px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23666'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 8px center}
.filter-select:focus{border-color:#e4f222;color:#e8e8e8}
.btn-export{margin-left:auto;padding:7px 14px;background:#e4f222;color:#08090a;border:none;border-radius:5px;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.3px}
.btn-export:hover{background:#f0f830}
.vis-count{color:#555;font-size:11px;font-family:monospace;white-space:nowrap}

/* finding cards */
.findings{display:flex;flex-direction:column;gap:10px}
.finding-card{background:#0f1012;border:1px solid #1a1d20;border-radius:8px;overflow:hidden;transition:border-color 0.15s}
.finding-card:hover{border-color:#2a2d30}
.finding-card.p1{border-left:3px solid #ff4444}
.finding-card.p2{border-left:3px solid #ff8800}
.finding-card.p3{border-left:3px solid #e4f222}
.finding-card.noise{border-left:3px solid #333;opacity:0.7}
.finding-card[data-status="proven"]{border-left-color:#44ff88!important;opacity:1}
.finding-card[data-status="disproven"]{border-left-color:#ff4444!important;opacity:0.5}
.finding-card[data-status="reported"]{border-left-color:#e4f222!important}
.card-header{display:flex;align-items:center;gap:8px;padding:10px 14px;cursor:pointer;user-select:none;flex-wrap:wrap}
.card-header:hover{background:rgba(255,255,255,0.02)}
.priority-badge{font-size:10px;font-weight:800;padding:3px 7px;border-radius:3px;letter-spacing:0.5px;flex-shrink:0;font-family:'JetBrains Mono',monospace}
.badge-p1{background:rgba(255,68,68,0.15);color:#ff4444;border:1px solid rgba(255,68,68,0.3)}
.badge-p2{background:rgba(255,136,0,0.15);color:#ff8800;border:1px solid rgba(255,136,0,0.3)}
.badge-p3{background:rgba(228,242,34,0.1);color:#e4f222;border:1px solid rgba(228,242,34,0.2)}
.badge-noise{background:rgba(255,255,255,0.03);color:#555;border:1px solid #222}
.score-pill{font-size:11px;font-family:'JetBrains Mono',monospace;color:#666;border:1px solid #1a1d20;border-radius:3px;padding:2px 6px;flex-shrink:0}
.fp-pill{font-size:10px;padding:2px 6px;border-radius:3px;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.fp-high{background:rgba(255,68,68,0.08);color:#ff6666;border:1px solid rgba(255,68,68,0.15)}
.fp-medium{background:rgba(255,136,0,0.08);color:#ff9922;border:1px solid rgba(255,136,0,0.15)}
.fp-low{background:rgba(68,255,68,0.08);color:#44ff88;border:1px solid rgba(68,255,68,0.15)}
.masvs-badge{font-size:10px;padding:2px 6px;border-radius:3px;font-family:'JetBrains Mono',monospace;font-weight:600;flex-shrink:0}
.masvs-STORAGE{background:rgba(59,130,246,0.1);color:#60a5fa;border:1px solid rgba(59,130,246,0.2)}
.masvs-CRYPTO{background:rgba(168,85,247,0.1);color:#c084fc;border:1px solid rgba(168,85,247,0.2)}
.masvs-AUTH{background:rgba(249,115,22,0.1);color:#fb923c;border:1px solid rgba(249,115,22,0.2)}
.masvs-NETWORK{background:rgba(20,184,166,0.1);color:#2dd4bf;border:1px solid rgba(20,184,166,0.2)}
.masvs-PLATFORM{background:rgba(6,182,212,0.1);color:#22d3ee;border:1px solid rgba(6,182,212,0.2)}
.masvs-CODE{background:rgba(34,197,94,0.1);color:#4ade80;border:1px solid rgba(34,197,94,0.2)}
.masvs-RESILIENCE{background:rgba(234,179,8,0.1);color:#facc15;border:1px solid rgba(234,179,8,0.2)}
.masvs-PRIVACY{background:rgba(236,72,153,0.1);color:#f472b6;border:1px solid rgba(236,72,153,0.2)}
.masvs-default{background:rgba(107,114,128,0.1);color:#9ca3af;border:1px solid rgba(107,114,128,0.2)}
.status-badge{font-size:10px;padding:2px 7px;border-radius:3px;font-family:'JetBrains Mono',monospace;font-weight:600;flex-shrink:0}
.status-noise{background:#111;color:#444;border:1px solid #222}
.status-investigating{background:rgba(255,136,0,0.1);color:#ff8800;border:1px solid rgba(255,136,0,0.3)}
.status-proven{background:rgba(68,255,136,0.1);color:#44ff88;border:1px solid rgba(68,255,136,0.3)}
.status-disproven{background:rgba(255,68,68,0.1);color:#ff4444;border:1px solid rgba(255,68,68,0.3)}
.status-reported{background:rgba(228,242,34,0.1);color:#e4f222;border:1px solid rgba(228,242,34,0.3)}
.card-title{flex:1;font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:100px}
.expand-icon{color:#444;font-size:11px;flex-shrink:0}

/* card body */
.card-body{padding:0 14px 14px;display:none}
.card-body.open{display:block}
.card-file{font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;color:#555;margin-bottom:10px;padding:6px 10px;background:#08090a;border-radius:4px;border:1px solid #1a1d20;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card-reasoning{font-size:12px;color:#aaa;margin-bottom:10px;line-height:1.6;padding:8px 10px;border-left:2px solid #1a1d20}
.card-chain{font-size:12px;color:#e4f222;margin-bottom:10px;padding:8px 10px;border-left:2px solid #e4f222;background:rgba(228,242,34,0.03);border-radius:0 4px 4px 0}
.action-block{position:relative;margin-bottom:10px}
.action-block pre{font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;background:#08090a;border:1px solid #1a1d20;border-radius:5px;padding:10px 36px 10px 12px;overflow-x:auto;color:#a8d8a8;white-space:pre-wrap;word-break:break-all;line-height:1.5}
.copy-btn{position:absolute;right:8px;top:8px;background:transparent;border:1px solid #2a2d30;border-radius:4px;padding:3px 7px;color:#555;font-size:10px;cursor:pointer;transition:all 0.15s}
.copy-btn:hover{border-color:#e4f222;color:#e4f222}
.copy-btn.copied{color:#44ff88;border-color:#44ff88}
.no-action{color:#333;font-size:11px;font-style:italic;padding:8px 10px;border:1px solid #1a1d20;border-radius:5px;background:#08090a;margin-bottom:10px}

/* status controls */
.card-controls{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.ctrl-label{font-size:11px;color:#555;font-family:'JetBrains Mono',monospace}
.status-select{background:#0f1012;border:1px solid #1a1d20;border-radius:4px;color:#e8e8e8;font-size:11px;padding:4px 8px;cursor:pointer;outline:none}
.status-select:focus{border-color:#e4f222}
.btn-proven{padding:4px 10px;background:rgba(68,255,136,0.08);border:1px solid rgba(68,255,136,0.25);border-radius:4px;color:#44ff88;font-size:11px;font-weight:700;cursor:pointer;transition:all 0.15s}
.btn-proven:hover{background:rgba(68,255,136,0.15);border-color:#44ff88}
.btn-disproven{padding:4px 10px;background:rgba(255,68,68,0.08);border:1px solid rgba(255,68,68,0.25);border-radius:4px;color:#ff4444;font-size:11px;font-weight:700;cursor:pointer;transition:all 0.15s}
.btn-disproven:hover{background:rgba(255,68,68,0.15);border-color:#ff4444}

/* notes */
.notes-block{margin-bottom:10px}
.notes-label{font-size:11px;color:#555;margin-bottom:4px}
.notes-area{width:100%;min-height:52px;background:#08090a;border:1px solid #1a1d20;border-radius:4px;color:#aaa;font-size:12px;padding:8px;resize:vertical;outline:none;font-family:'Inter',system-ui,sans-serif;line-height:1.5}
.notes-area:focus{border-color:#e4f222}
.notes-area::placeholder{color:#333}

.hidden{display:none!important}
.empty-state{text-align:center;padding:60px 20px;color:#333;font-size:14px}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #1a1d20;color:#333;font-size:11px;font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between}

@media print{
  body{background:#fff;color:#000}
  .finding-card{border:1px solid #ccc;page-break-inside:avoid}
  .toolbar,.btn-export,.copy-btn,.card-controls,.notes-area{display:none}
  .card-body{display:block!important}
  .finding-card[data-status="disproven"],.finding-card[data-status="noise"]{display:none}
}
"""

# ── JS ────────────────────────────────────────────────────────────────────────

JS = r"""
(function(){
  var STORE='mobsf_triage_v2';

  function loadStore(){
    try{return JSON.parse(localStorage.getItem(STORE)||'{}');}catch(e){return {};}
  }
  function saveStore(s){localStorage.setItem(STORE,JSON.stringify(s));}

  // Simple djb2 hash for localStorage keys
  function hashKey(s){
    var h=5381;
    for(var i=0;i<s.length;i++){h=((h<<5)+h)^s.charCodeAt(i);}
    return (h>>>0).toString(16);
  }

  var store=loadStore();

  /* ── restore persisted state ── */
  document.querySelectorAll('.finding-card').forEach(function(card){
    var key=card.dataset.key;
    if(!key)return;
    var saved=store[key]||{};
    if(saved.status){
      card.dataset.status=saved.status;
      var sel=card.querySelector('.status-select');
      if(sel)sel.value=saved.status;
      updateStatusBadge(card,saved.status);
    }
    if(saved.notes){
      var ta=card.querySelector('.notes-area');
      if(ta)ta.value=saved.notes;
    }
  });

  function updateStatusBadge(card,status){
    var badge=card.querySelector('.status-badge');
    if(!badge)return;
    badge.className='status-badge status-'+status;
    var labels={noise:'noise',investigating:'investigating',proven:'proven',disproven:'disproven',reported:'reported'};
    badge.textContent=labels[status]||status;
  }

  function setStatus(card,status){
    var key=card.dataset.key;
    card.dataset.status=status;
    var saved=store[key]||{};
    saved.status=status;
    store[key]=saved;
    saveStore(store);
    updateStatusBadge(card,status);
    var sel=card.querySelector('.status-select');
    if(sel)sel.value=status;
    updateProgress();
    applyFilters();
  }

  /* ── controls wiring ── */
  document.querySelectorAll('.status-select').forEach(function(sel){
    sel.addEventListener('change',function(e){
      e.stopPropagation();
      setStatus(sel.closest('.finding-card'),sel.value);
    });
  });
  document.querySelectorAll('.btn-proven').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      setStatus(btn.closest('.finding-card'),'proven');
    });
  });
  document.querySelectorAll('.btn-disproven').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      setStatus(btn.closest('.finding-card'),'disproven');
    });
  });

  /* ── notes ── */
  document.querySelectorAll('.notes-area').forEach(function(ta){
    ta.addEventListener('input',function(){
      var card=ta.closest('.finding-card');
      var key=card.dataset.key;
      var saved=store[key]||{};
      saved.notes=ta.value;
      store[key]=saved;
      saveStore(store);
    });
    ta.addEventListener('click',function(e){e.stopPropagation();});
  });

  /* ── expand/collapse ── */
  document.querySelectorAll('.card-header').forEach(function(h){
    h.addEventListener('click',function(){
      var body=h.nextElementSibling;
      var icon=h.querySelector('.expand-icon');
      body.classList.toggle('open');
      icon.textContent=body.classList.contains('open')?'▲':'▼';
    });
  });

  /* ── copy buttons ── */
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

  /* ── filters ── */
  function applyFilters(){
    var q=(document.getElementById('search-box').value||'').toLowerCase();
    var pri=document.getElementById('filter-priority').value;
    var sta=document.getElementById('filter-status').value;
    var vis=0;
    document.querySelectorAll('.finding-card').forEach(function(c){
      var matchPri=pri==='all'||c.dataset.priority===pri;
      var matchSta=sta==='all'||c.dataset.status===sta;
      var matchQ=!q||c.textContent.toLowerCase().includes(q);
      var show=matchPri&&matchSta&&matchQ;
      c.classList.toggle('hidden',!show);
      if(show)vis++;
    });
    document.getElementById('visible-count').textContent=vis+' findings';
  }

  document.getElementById('filter-priority').addEventListener('change',applyFilters);
  document.getElementById('filter-status').addEventListener('change',applyFilters);
  document.getElementById('search-box').addEventListener('input',applyFilters);

  /* ── progress ── */
  function updateProgress(){
    var total=document.querySelectorAll('.finding-card').length;
    var proven=document.querySelectorAll('.finding-card[data-status="proven"]').length;
    var reported=document.querySelectorAll('.finding-card[data-status="reported"]').length;
    var investigating=document.querySelectorAll('.finding-card[data-status="investigating"]').length;
    var disproven=document.querySelectorAll('.finding-card[data-status="disproven"]').length;
    var triaged=proven+reported+disproven;
    var pct=total>0?Math.round(triaged/total*100):0;
    var fill=document.getElementById('prog-fill');
    if(fill)fill.style.width=pct+'%';
    var label=document.getElementById('prog-label');
    if(label)label.textContent=triaged+'/'+total+' triaged ('+pct+'%)';
    var el;
    if((el=document.getElementById('prog-proven')))el.textContent=proven+' proven';
    if((el=document.getElementById('prog-reported')))el.textContent=reported+' reported';
    if((el=document.getElementById('prog-investigating')))el.textContent=investigating+' investigating';
    if((el=document.getElementById('prog-disproven')))el.textContent=disproven+' disproven';
  }

  /* ── export JSON ── */
  document.getElementById('btn-export').addEventListener('click',function(){
    var out=[];
    document.querySelectorAll('.finding-card').forEach(function(c){
      var key=c.dataset.key||'';
      var saved=store[key]||{};
      var title=c.querySelector('.card-title').textContent.trim();
      var file=c.querySelector('.card-file');
      var reasoning=c.querySelector('.card-reasoning');
      var action=c.querySelector('.action-block pre');
      var mavsEl=c.querySelector('.masvs-badge');
      out.push({
        title:title,
        file:file?file.textContent.trim():'',
        priority:c.dataset.priority||'',
        bounty_score:parseInt(c.dataset.score||'0',10),
        status:c.dataset.status||'noise',
        fp_risk:(c.querySelector('.fp-pill')||{textContent:''}).textContent.replace('FP:',''),
        reasoning:reasoning?reasoning.textContent.trim():'',
        next_action:action?action.textContent.trim():'',
        masvs_id:mavsEl?mavsEl.textContent:'',
        notes:saved.notes||'',
      });
    });
    var json=JSON.stringify(out,null,2);
    navigator.clipboard.writeText(json);
    var btn=document.getElementById('btn-export');
    btn.textContent='✓ Copied JSON';
    setTimeout(function(){btn.textContent='Export JSON';},2000);
  });

  updateProgress();
  applyFilters();
})();
"""

# ── HTML generation ────────────────────────────────────────────────────────────

PRIORITY_ORDER = {'P1': 0, 'P2': 1, 'P3': 2, 'noise': 3}

MASVS_CATEGORIES = {
    'STORAGE': 'STORAGE',
    'CRYPTO': 'CRYPTO',
    'AUTH': 'AUTH',
    'NETWORK': 'NETWORK',
    'PLATFORM': 'PLATFORM',
    'CODE': 'CODE',
    'RESILIENCE': 'RESILIENCE',
    'PRIVACY': 'PRIVACY',
}


def _e(text: str) -> str:
    return _html.escape(str(text), quote=True)


def _hashkey(title: str, file_path: str) -> str:
    """Simple stable key for a finding — used as localStorage key in JS."""
    import hashlib
    return hashlib.sha1(f'{title}::{file_path}'.encode()).hexdigest()[:12]


def _priority_badge(priority: str) -> str:
    cls = {'P1': 'badge-p1', 'P2': 'badge-p2', 'P3': 'badge-p3'}.get(priority, 'badge-noise')
    return f'<span class="priority-badge {cls}">{_e(priority)}</span>'


def _fp_pill(fp_risk: str) -> str:
    cls = {'low': 'fp-low', 'medium': 'fp-medium', 'high': 'fp-high'}.get(fp_risk, 'fp-medium')
    return f'<span class="fp-pill {cls}">FP:{_e(fp_risk)}</span>'


def _masvs_badge(masvs_id: str) -> str:
    if not masvs_id:
        return ''
    category = masvs_id.split('-')[0].upper()
    css_cls = MASVS_CATEGORIES.get(category, 'default')
    return f'<span class="masvs-badge masvs-{_e(css_cls)}">{_e(masvs_id)}</span>'


def _status_badge(status: str = 'noise') -> str:
    return f'<span class="status-badge status-{_e(status)}">{_e(status)}</span>'


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
    masvs_id = triage.get('masvs_id', '') or fp_filter.get('masvs_id', '') or finding.get('masvs_id', '')
    card_key = _hashkey(title, file_path)

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
    masvs_html = _masvs_badge(masvs_id)

    status_select = (
        '<select class="status-select" onclick="event.stopPropagation()">'
        '<option value="noise">noise</option>'
        '<option value="investigating">investigating</option>'
        '<option value="proven">proven</option>'
        '<option value="disproven">disproven</option>'
        '<option value="reported">reported</option>'
        '</select>'
    )

    return (
        f'<div class="finding-card {priority.lower()}" '
        f'data-priority="{_e(priority)}" data-score="{_e(str(score))}" '
        f'data-status="noise" data-key="{_e(card_key)}">'
        # header
        f'<div class="card-header">'
        f'{_priority_badge(priority)}'
        f'<span class="score-pill">{_e(str(score))}/100</span>'
        f'{_fp_pill(fp_risk)}'
        f'{masvs_html}'
        f'{_status_badge()}'
        f'<span class="card-title">{_e(title)}</span>'
        f'<span class="expand-icon">&#9660;</span>'
        f'</div>'
        # body
        f'<div class="card-body">'
        f'<div class="card-file">{_e(file_path or "—")}</div>'
        f'<div class="card-reasoning">{_e(reasoning)}</div>'
        f'{chain_html}'
        f'{action_html}'
        # status controls
        f'<div class="card-controls">'
        f'<span class="ctrl-label">Status:</span>'
        f'{status_select}'
        f'<button class="btn-proven">&#10003; Proven</button>'
        f'<button class="btn-disproven">&#10007; Disproven</button>'
        f'</div>'
        # analyst notes
        f'<div class="notes-block">'
        f'<div class="notes-label">Analyst notes</div>'
        f'<textarea class="notes-area" placeholder="Add investigation notes…"></textarea>'
        f'</div>'
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

    # LLM banner
    llm_active = llm.get('available', False) and llm.get('provider', 'none') != 'none'
    batch_note = ''
    if llm_active:
        queued = llm.get('queued', 0)
        batch_note = f'<span class="llm-batch">Batch mode: {queued} findings queued</span>'
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
        f'{batch_note}'
        f'</div>'
    )

    # Stats row
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

    # Progress bar
    progress_html = (
        '<div class="progress-row">'
        '<div class="progress-label">'
        '<span id="prog-label">0/' + str(total) + ' triaged (0%)</span>'
        '</div>'
        '<div class="progress-track"><div class="progress-fill" id="prog-fill" style="width:0%"></div></div>'
        '<div class="progress-counts">'
        '<span class="prog-pill prog-proven" id="prog-proven">0 proven</span>'
        '<span class="prog-pill prog-reported" id="prog-reported">0 reported</span>'
        '<span class="prog-pill prog-investigating" id="prog-investigating">0 investigating</span>'
        '<span class="prog-pill prog-disproven" id="prog-disproven">0 disproven</span>'
        '</div>'
        '</div>'
    )

    # Toolbar — dropdowns instead of buttons
    toolbar_html = (
        '<div class="toolbar">'
        '<input id="search-box" class="search-box" type="text" placeholder="Search findings…">'
        '<select id="filter-priority" class="filter-select">'
        '<option value="all">All priorities</option>'
        '<option value="P1">P1</option>'
        '<option value="P2">P2</option>'
        '<option value="P3">P3</option>'
        '<option value="noise">Noise</option>'
        '</select>'
        '<select id="filter-status" class="filter-select">'
        '<option value="all">All statuses</option>'
        '<option value="noise">noise</option>'
        '<option value="investigating">investigating</option>'
        '<option value="proven">proven</option>'
        '<option value="disproven">disproven</option>'
        '<option value="reported">reported</option>'
        '</select>'
        '<span id="visible-count" class="vis-count"></span>'
        '<button class="btn-export" id="btn-export">Export JSON</button>'
        '</div>'
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
        f'{progress_html}\n'
        f'{toolbar_html}\n'
        f'<div class="findings">\n{cards_html}\n</div>\n'
        f'<div class="footer"><span>ProwlrBot / mobsf-binary</span><span>{_e(now)}</span></div>\n'
        '</div>\n'
        f'<script>{JS}</script>\n'
        '</body>\n'
        '</html>'
    )
