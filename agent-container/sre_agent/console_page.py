"""The agent console's single page: status strip, symptom question bar, alerts and cases, live reasoning (with every raw
MCP call), and the war-room brief with Approve / Reject. Inline CSS and JavaScript; every value goes in with textContent."""

import html

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TukTukPay AI SRE agent</title><meta name="console-token" content="__TOKEN__">
<style>
:root{--bg:#0f172a;--panel:#1e293b;--panel2:#243247;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--teal:#2dd4bf;--good:#22c55e;--warn:#f59e0b;--bad:#ef4444;--violet:#a78bfa;--mono:ui-monospace,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:10px;padding:10px 18px;border-bottom:1px solid var(--border)}
header h1{margin:0;font-size:16px}.pill{font:11px var(--mono);color:var(--teal);border:1px solid var(--border);border-radius:999px;padding:2px 9px}
.strip{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;padding:12px 18px}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 12px;min-width:0}
.tile .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}.tile .v{font-size:22px;font-weight:600;line-height:1.2}.tile .s{font-size:11px;color:var(--muted);overflow-wrap:anywhere}
.tile .v.bad{color:var(--bad)}.tile .v.warn{color:var(--warn)}.tile .v.good{color:var(--good)}
.fchip{display:inline-block;font:11px var(--mono);border:1px solid var(--bad);color:var(--bad);border-radius:999px;padding:1px 8px;margin:2px 4px 0 0}.fchip.load{border-color:var(--muted);color:var(--muted)}
.ask{display:flex;gap:8px;padding:0 18px}.ask input{flex:1;background:var(--panel);border:1px solid var(--border);border-radius:9px;color:var(--text);padding:11px 14px;font-size:14px}
.ask button{background:linear-gradient(90deg,#14b8a6,#2dd4bf);color:#042f2e;border:0;border-radius:9px;padding:0 20px;font-weight:700;cursor:pointer}
.chips{display:flex;flex-wrap:wrap;gap:8px;padding:8px 18px 12px}.chips button{background:transparent;color:var(--text);border:1px solid var(--border);border-radius:999px;padding:4px 12px;cursor:pointer;font-size:12px}.chips button:hover{border-color:var(--teal)}
.grid{display:grid;grid-template-columns:260px minmax(0,1.25fr) minmax(0,1fr);gap:12px;padding:0 18px 18px;height:calc(100vh - 222px);min-height:520px}
.pane{background:var(--panel);border:1px solid var(--border);border-radius:12px;min-width:0;display:flex;flex-direction:column;overflow:hidden}
.pane h2{margin:0;padding:10px 14px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--teal);border-bottom:1px solid var(--border)}
.scroll{overflow:auto;padding:10px 12px;flex:1}
.item{background:var(--panel2);border:1px solid var(--border);border-radius:9px;padding:7px 9px;margin:0 0 7px;cursor:pointer;display:grid;gap:2px;overflow-wrap:anywhere}
.item:hover,.item.on{border-color:var(--teal)}.item .t{font-weight:600;font-size:12px}.item .s{font-size:11px;color:var(--muted)}
.item button{justify-self:start;background:var(--teal);color:#042f2e;border:0;border-radius:6px;padding:2px 10px;font-weight:600;cursor:pointer;margin-top:3px;font-size:12px}
.sub{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:10px 2px 6px;display:flex;align-items:center;gap:6px}
.clr{margin-left:auto;display:flex;gap:6px;align-items:center;white-space:nowrap;text-transform:none;letter-spacing:0}.clr button{background:var(--teal);color:#042f2e;border:0;border-radius:6px;padding:2px 10px;font-weight:700;cursor:pointer;font-size:12px}.clr .link{background:transparent;color:var(--teal);padding:2px 4px;text-decoration:underline}
.row{display:grid;grid-template-columns:52px minmax(0,1fr);gap:8px;padding:3px 0;overflow-wrap:anywhere}.row .at{font:11px var(--mono);color:var(--muted);padding-top:3px;text-align:right}
.box{border:1px solid var(--border);border-radius:9px;padding:7px 10px;background:#18233a}.box.think{border-left:3px solid var(--violet)}.box.act{border-left:3px solid var(--warn)}.box.done{border-left:3px solid var(--good)}.box.err{border-left:3px solid var(--bad)}.box.user{background:#134e4a;border-color:#115e59}
.box .who{font-size:11px;color:var(--muted);margin-bottom:3px}
.mcp{font:12px var(--mono);color:#7dd3fc}.mcp .srv{color:var(--muted)}.mcp .ms{color:var(--good)}.mcp .ms.bad{color:var(--bad)}
.plain{font-size:12px;color:var(--muted)}.why{font-size:12px}.why b{color:var(--violet);font-weight:600}
details{margin:3px 0}summary{cursor:pointer;color:var(--muted);font-size:12px}details[open] summary{color:var(--teal)}
pre{white-space:pre-wrap;word-break:break-all;font:11px var(--mono);background:var(--panel2);border:1px solid var(--border);border-radius:6px;padding:6px 8px;margin:4px 0 0;max-height:220px;overflow:auto}
.chip{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px;border:1px solid var(--muted);color:var(--muted);margin-right:5px}
.chip.validated,.chip.metric,.chip.trace,.chip.log{color:var(--good);border-color:var(--good)}.chip.inconclusive{color:var(--warn);border-color:var(--warn)}
.cat{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.1em;padding:3px 10px;border-radius:6px;background:#3b1d4a;color:#f0abfc}
.brief h3{font-size:20px;margin:8px 0 10px;line-height:1.25}.kv{display:grid;grid-template-columns:120px minmax(0,1fr);gap:4px 10px;font-size:13px;margin-bottom:8px}.kv .k{color:var(--muted)}
.brief ul,.brief ol{margin:3px 0 8px;padding-left:18px;font-size:13px}.brief .lab{font-size:12px;color:var(--muted);margin-top:8px}
.action{border:1px dashed var(--warn);border-radius:10px;padding:10px 12px;margin-top:10px}.action b{font-size:14px}
.btns{display:flex;gap:8px;margin-top:9px}.btns button{border:0;border-radius:8px;padding:7px 16px;font-weight:700;cursor:pointer}
.approve{background:linear-gradient(90deg,#16a34a,#22c55e);color:#052e16}.reject{background:transparent;color:var(--text);border:1px solid var(--border)!important}
.follow{display:flex;gap:8px;padding:8px 10px;border-top:1px solid var(--border)}.follow input{flex:1;background:var(--panel2);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:8px 10px}
.follow button{background:var(--teal);border:0;border-radius:8px;padding:0 14px;font-weight:600;cursor:pointer}
.follow button.stopbtn{background:transparent;color:var(--bad);border:1px solid var(--bad)}.follow button.stopbtn:disabled{opacity:.6;cursor:default}
.empty{color:var(--muted);text-align:center;margin:40px 12px}
dialog.modal{background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:14px;padding:20px 22px 18px;width:min(500px,92vw);box-shadow:0 24px 70px rgba(0,0,0,.55)}
dialog.modal::backdrop{background:rgba(2,6,23,.7);backdrop-filter:blur(2px)}
.modal h4{margin:0 0 6px;font-size:16px}.modal .msg{margin:0 0 12px;color:var(--muted);font-size:13px}.modal .msg b{color:var(--text)}
.modal label{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:4px 0 6px}
.modal textarea{width:100%;min-height:68px;background:var(--panel2);border:1px solid var(--border);border-radius:9px;color:var(--text);padding:9px 11px;font-family:inherit;font-size:13px;line-height:1.4;resize:vertical}
.modal textarea:focus{outline:none;border-color:var(--teal)}
.modal .quick{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}.modal .quick button{background:transparent;color:var(--text);border:1px solid var(--border);border-radius:999px;padding:3px 11px;font-size:12px;cursor:pointer}.modal .quick button:hover,.modal .quick button.on{border-color:var(--teal);color:var(--teal)}
.modal .foot{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}.modal .foot button{border:0;border-radius:8px;padding:8px 18px;font-weight:700;cursor:pointer}
.modal .go{background:linear-gradient(90deg,#14b8a6,#2dd4bf);color:#042f2e}.modal .go.danger{background:linear-gradient(90deg,#dc2626,#ef4444);color:#fff}
#toast{position:fixed;right:18px;bottom:18px;max-width:min(440px,90vw);background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--teal);border-radius:10px;padding:10px 14px;font-size:13px;box-shadow:0 12px 40px rgba(0,0,0,.45);opacity:0;transform:translateY(8px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:10}
#toast.show{opacity:1;transform:none}#toast.bad{border-left-color:var(--bad)}
@media (max-width:1100px){.strip{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr;height:auto}.pane{min-height:360px}}
.banner{border:2px solid var(--teal);background:rgba(45,212,191,.12);border-radius:10px;padding:10px 12px;margin:0 0 12px;display:grid;gap:6px}
.banner .h{font-size:15px;font-weight:700}.banner .s{font-size:13px;color:var(--text)}
.banner button,.tag{background:var(--teal);color:#042f2e;border:0;border-radius:6px;padding:5px 14px;font-weight:700;cursor:pointer;font-size:13px;justify-self:start}
.banner.warn{border-color:var(--warn);background:rgba(245,158,11,.12)}.banner.warn button{background:var(--warn);color:#2b1a02}
.item.merged{border:2px solid var(--warn);background:rgba(245,158,11,.12)}.item.merged.on,.item.merged:hover{border-color:#fbbf24}
.tag.warn{background:var(--warn);color:#2b1a02}
.tag{display:inline-block;font-size:11px;padding:2px 9px;margin-right:6px;letter-spacing:.03em}
.ties .item{font-size:13px;border-color:var(--teal)}.ties .item .s{font-size:12px}.ties .head{font-size:14px;font-weight:700;color:var(--teal);margin:10px 0 6px}
.ties .foot{margin-top:6px}.ties .foot button{padding:5px 14px;font-size:13px}.ties .foot .go{background:var(--teal);color:#042f2e}
</style></head><body>
<header><h1>TukTukPay · AI SRE agent</h1><span class="pill" id="mode">…</span><span style="flex:1"></span><span class="pill">env tuktukpay-demo</span></header>
<div class="strip" id="strip"><div class="tile"><div class="l">Status</div><div class="v">…</div><div class="s">loading</div></div></div>
<form class="ask" id="askform"><input id="symptom" placeholder="Describe what you see, e.g. “Merchants report card payments failing at checkout. What is going on and what should we do?”" autocomplete="off"><button type="submit">Investigate</button></form>
<div class="chips" id="chips"></div>
<div class="grid">
  <section class="pane"><h2>Alerts &amp; cases</h2><div class="scroll"><div class="sub">Open alerts <span class="clr" id="clr-alerts"></span></div><div id="alerts"><div class="item"><span class="s">loading…</span></div></div><div class="sub">Recent cases <span class="clr" id="clr-cases"></span></div><div id="cases"></div></div></section>
  <section class="pane"><h2>Agent reasoning (live)</h2><div class="scroll" id="trace"><div class="empty">Ask a question above, or press <b>Triage</b> on an alert. Every step appears here as it happens: the evidence code collects, each model step with its reasoning, and every raw MCP call to Splunk Observability Cloud and Splunk Enterprise with its arguments and timing.</div></div>
    <form class="follow" id="follow"><input id="q" placeholder="Follow-up question about this case…" autocomplete="off" disabled><button type="button" id="stop" class="stopbtn" hidden title="Stop the running investigation or follow-up at its next checkpoint">Stop</button><button type="submit">Ask</button></form></section>
  <section class="pane"><h2>War-room brief</h2><div class="scroll brief" id="brief"><div class="empty">The brief appears when the investigation concludes: impact, root cause, the team to page, the evidence, and the recommended action for a human to approve.</div></div></section>
</div>
<div id="toast" role="status" aria-live="polite"></div>
<script>
'use strict';
window.addEventListener('error', (e) => { const a = document.getElementById('alerts'); if (a) a.textContent = 'Page error: ' + e.message; });
window.addEventListener('unhandledrejection', (e) => { const a = document.getElementById('alerts'); if (a) a.textContent = 'Request failed: ' + ((e.reason && e.reason.message) || e.reason); });
const TOKEN = document.querySelector('meta[name=console-token]').content;
const H = { 'X-Console-Token': TOKEN, 'Content-Type': 'application/json' };
const $ = (s) => document.querySelector(s);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
const api = (p, body) => fetch(p, body ? { method: 'POST', headers: H, body: JSON.stringify(body) } : { headers: H }).then(r => r.json());
const short = (d) => String(d || '').replace(/^TukTukPay \[[^\]]+\] /, '').replace(/^Reported symptom \(operator question\): /, 'question: ');
const mdl = (m) => String(m || '').replace('global.anthropic.', '');
const CATEGORY = { dependency_degraded: 'DEPENDENCY', config_change: 'CHANGE', resource_exhaustion: 'INFRASTRUCTURE', bad_release: 'RELEASE', capacity: 'CAPACITY',
  abuse_or_governance: 'GOVERNANCE', application_bug: 'APPLICATION', unknown: 'UNDETERMINED' };
const PRESETS = [
  ['Card payments failing', 'Merchants report card payments failing or timing out at checkout. What is going on and what should we do?'],
  ['Checkout is slow', 'Checkout is slow for customers right now. Find the cause.'],
  ['Agent payments blocked', 'Shopping agents say their payments are being blocked. Is something broken?'],
  ['Copilot cost spike', 'The merchant copilot bill is spiking. What is driving it?'],
  ['Pods restarting', 'Some pods keep restarting. Which ones and why?'],
  ['Webhooks failing', 'A merchant says they stopped receiving payment webhooks. Investigate.'],
];
const freshCalls = () => ({ 'o11y-mcp-gateway': 0, 'splunk-mcp-server': 0, 'splunk-rest': 0 });
let current = null, es = null, t0 = null, calls = freshCalls(), briefShown = false;
function setRunning(on) { const b = $('#stop'); if (!b) return; b.hidden = !on; if (on) { b.disabled = false; b.textContent = 'Stop'; } }

function rich(text) {   // tiny safe formatter: **bold**, `code`, "- " bullets, headings; text nodes only
  const out = el('div'); let ul = null;
  String(text || '').split('\n').forEach(line => {
    const bullet = /^\s*[-*] /.test(line), head = /^#{1,4} /.test(line);
    if (!line.trim()) { ul = null; return; }
    let target = out;
    if (bullet) { if (!ul) { ul = el('ul'); out.append(ul); } target = ul; } else ul = null;
    const node = el(bullet ? 'li' : head ? 'b' : 'p'); node.style.margin = bullet ? '2px 0' : '3px 0'; if (head) node.style.display = 'block';
    line.replace(/^\s*[-*] |^#{1,4} /, '').split(/(\*\*[^*]+\*\*|`[^`]+`)/).forEach(part => {
      if (/^\*\*[^*]+\*\*$/.test(part)) node.append(el('b', null, part.slice(2, -2)));
      else if (/^`[^`]+`$/.test(part)) { const c = el('code', null, part.slice(1, -1)); c.style.font = '12px var(--mono)'; node.append(c); }
      else node.append(document.createTextNode(part));
    });
    target.append(node);
  });
  return out;
}
function details(label, text) { const d = el('details'); d.append(el('summary', null, label), el('pre', null, text || '')); return d; }
function at(e) { const t = Number(e.t) || Date.parse(e.ts) / 1000; if (t0 == null) t0 = t; return '+' + Math.max(0, t - t0).toFixed(1) + 's'; }
function row(e, node) { const r = el('div', 'row'); r.append(el('div', 'at', at(e)), node); $('#trace').append(r); $('#trace').scrollTop = $('#trace').scrollHeight; return r; }
function box(cls, who, nodes) { const b = el('div', 'box ' + (cls || '')); if (who) b.append(el('div', 'who', who)); (nodes || []).forEach(n => n && b.append(typeof n === 'string' ? el('div', null, n) : n)); return b; }
function plain(t) { return el('div', 'plain', t); }
const REL = { likely_cause_of: 'may be the cause of', likely_symptom_of: 'may be a symptom of', same_service: 'same service as' };
const relPath = (j) => (j.path || []).length > 1 ? j.path.join(' → ') : String(j.rule || j.relation || '').replace(/_/g, ' ');
const hhmm = (ts) => ts ? String(ts).slice(11, 16) + 'Z' : '';
const who = (by) => String(by || '').replace(/@console$/, '');
function groupedNode(list) {   // merged / added alerts as highlighted chips; topology joins as plain text
  if (!(list || []).length) return null; const w = el('div');
  list.forEach(j => { const line = el('div');
    if (j.rule === 'merged') { const t = el('span', 'tag', `MERGED from ${j.from_case || 'another case'}`); if (j.from_case) t.onclick = () => open(j.from_case); line.append(t, document.createTextNode(`${short(j.detector)}${j.by ? ` · by ${who(j.by)}` : ''}${j.at ? ` at ${hhmm(j.at)}` : ''}`)); }
    else if (j.rule === 'added') line.append(el('span', 'tag', 'ADDED'), document.createTextNode(`${short(j.detector)}${j.by ? ` · by ${who(j.by)}` : ''}${j.at ? ` at ${hhmm(j.at)}` : ''}`));
    else line.append(document.createTextNode(`${short(j.detector)}: ${relPath(j)}${j.gap_s != null ? ` (${j.gap_s} s after the case opened)` : ''}`));
    w.append(line); });
  return w;
}
function mergeBanners(e) {   // highlighted, like the Close case button: merged away, or alerts added after the brief
  const out = [];
  if (e.merged_into) {
    const bn = el('div', 'banner'); bn.append(el('div', 'h', `Merged into case ${e.merged_into}`),
      el('div', 's', `${e.merged_by ? 'By ' + who(e.merged_by) + (e.merged_at ? ' at ' + hhmm(e.merged_at) : '') + '. ' : ''}This case is closed; its alerts are now investigated in ${e.merged_into}. The brief below is this case's own, from before the merge.`));
    const go = el('button', null, `Open ${e.merged_into}`); go.onclick = () => open(e.merged_into); bn.append(go); out.push(bn);
  }
  const un = e.unreviewed_alerts || [];
  if (un.length && e.state !== 'closed') {
    const bn = el('div', 'banner warn'); bn.append(el('div', 'h', `${un.length} alert${un.length > 1 ? 's' : ''} merged in after this brief was written`),
      el('div', 's', `${un.map(short).join(' + ')}. The root cause and action below do not consider ${un.length > 1 ? 'them' : 'it'} yet.`));
    const rr = el('button', null, 'Re-run RCA with all alerts'); rr.onclick = async () => { if (!(await confirmRerun('all alerts of this case'))) return; rr.disabled = true;
      api('/api/rerun', { case_id: e.case_id }).then(r => { if (r.case_id) { open(r.case_id); loadSide(); } else { rr.disabled = false; toast(r.error, true); } }); };
    bn.append(rr); out.push(bn);
  }
  return out;
}
const relText = (rel, other) => rel === 'same_service' ? `Same service as ${other}` : rel === 'likely_cause_of' ? `This case may be the cause of ${other}` : `This case may be a symptom of ${other}`;
async function loadTies(cid, slot) {   // fetched when shown, so case states and firing alerts are current
  const v = await api(`/api/ties/${encodeURIComponent(cid)}`); slot.replaceChildren(); if (v.error) return;
  if (!(v.cases || []).length && !(v.alerts || []).length) return;
  slot.classList.add('ties'); slot.append(el('div', 'head', 'Possible ties (service map) — not merged'));
  const card = (lines, buttons) => { const r = el('div', 'item'); lines.forEach(([cls, t]) => { const n = el('div', cls, t); if (!cls) n.style.fontWeight = '600'; r.append(n); }); const f = el('div', 'foot'); buttons.forEach(b => f.append(b)); r.append(f); slot.append(r); return r; };
  const btn = (label, cls, fn) => { const b = el('button', cls, label); b.type = 'button'; b.onclick = fn; return b; };
  (v.alerts || []).forEach(a => {
    let add; const r = card([[null, `${relText(a.relation, 'an open alert with no case')}: ${short(a.detector)}`],
      ['s', `${(a.path || []).join(' → ')} · firing since ${String(a.since || '').replace('T', ' ').slice(0, 16)} UTC`]], [
      btn('Triage separately', null, () => start({ incident_id: a.incident_id })),
      add = btn('Add to this case', 'go', async () => { add.disabled = true; const x = await api('/api/tie/attach', { case_id: cid, incident_id: a.incident_id });
        if (x.error) { toast(x.error, true); add.disabled = false; return; } toast(`Added ${short(a.detector)} to ${cid}. ${x.note || ''}`); refreshCase(cid); loadSide(); })]);
  });
  (v.cases || []).forEach(t => {
    const g = Number(t.gap_s) || 0; let m, d;
    const r = card([[null, `${relText(t.relation, 'case ' + t.case_id)}: ${(t.detectors || []).map(short).join(' + ')}`],
      ['s', `case ${String(t.state || '').replace(/_/g, ' ')} · alert ${t.alert_firing ? 'still firing' : 'cleared'} · ${(t.path || []).join(' → ')} · opened ${Math.abs(g)} s ${g >= 0 ? 'before' : 'after'} this case`]], [
      btn('Open', null, () => open(t.case_id)),
      d = btn('Not related', 'reject', async () => { m.disabled = d.disabled = true; const x = await api('/api/tie/dismiss', { case_id: cid, other_case_id: t.case_id });
        if (x.error) { toast(x.error, true); m.disabled = d.disabled = false; return; } toast(`Tie to ${t.case_id} dismissed`); r.remove(); loadSide(); }),
      m = btn('Merge into this case', 'go', async () => { m.disabled = d.disabled = true; const x = await api('/api/tie/merge', { case_id: cid, other_case_id: t.case_id });
        if (x.error) { toast(x.error, true); m.disabled = d.disabled = false; return; } toast(`Merged ${t.case_id} into ${cid}. ${x.note || ''}`); refreshCase(cid); loadSide(); })]);
  });
}

function render(e) {
  if (REFRESH_ON.has(e.event) && e.case_id === current) refreshSoon(current);
  switch (e.event) {
    case 'sre.case.opened': return row(e, plain(`Case ${e.case_id} opened for ${(e.detectors || []).map(short).join(' + ')}`));
    case 'sre.case.incident_attached': return row(e, plain(`Added ${short(e.detector)} to case ${e.case_id}: ${relPath(e)} (${e.gap_s} s after it opened)`));
    case 'sre.case.tie_suggested': return row(e, plain(`Possible tie: this case ${REL[e.relation] || e.relation} ${e.other_case} (${(e.other_detectors || []).map(short).join(' + ')}) via ${(e.path || []).join(' → ')}`));
    case 'sre.case.incident_added': return row(e, plain(`Added ${short(e.detector)} to case ${e.case_id} (by ${e.by})`));
    case 'sre.case.merged': return row(e, plain(`Case ${e.merged_case} merged into ${e.case_id} by ${who(e.by)}`));
    case 'sre.case.merged_away': return row(e, plain(`This case was merged into ${e.into} by ${who(e.by)}`));
    case 'sre.case.tie_dismissed': return row(e, plain(`Tie with ${e.other_case} marked not related by ${who(e.by)}`));
    case 'sre.console.starting': setRunning(true); return row(e, plain('Connecting to Observability Cloud (MCP gateway) and Splunk Enterprise (MCP Server)…'));
    case 'sre.case.investigating': setRunning(true); return row(e, plain('Collecting evidence by code before the model sees anything…'));
    case 'sre.mcp.call': {
      calls[e.server] = (calls[e.server] || 0) + 1;
      const d = el('details'); const s = el('summary'); const m = el('span', 'mcp');
      m.append(el('span', 'srv', e.server === 'splunk-mcp-server' ? 'splunk ▸ ' : e.server === 'splunk-rest' ? 'splunk-rest ▸ ' : 'o11y ▸ '), document.createTextNode(e.tool + ' '),
        el('span', 'ms' + (e.ok ? '' : ' bad'), (e.ok ? '✓ ' : '✕ ') + e.ms + ' ms'));
      s.append(m); d.append(s, el('pre', null, (e.params || '') + (e.error ? '\n\nerror: ' + e.error : '')));
      return row(e, d);
    }
    case 'sre.rca.evidence': return row(e, details(`evidence ready: ${String(e.section).replace(/_/g, ' ')} — ${e.summary}`, e.preview));
    case 'sre.rca.step': {
      if (e.stop_reason === 'evidence_check') return row(e, box('act', 'evidence check by code', [rich(e.reasoning || 'The answer lacked a metric/trace or log signal; one more round requested.')]));
      const nodes = [];
      if (e.reasoning) nodes.push(rich(e.reasoning));
      if (e.text) nodes.push(el('div', null, e.text));
      (e.tool_calls || []).forEach(c => { const w = el('div', 'why'); w.append(el('b', null, 'Next: '), document.createTextNode((c.args && c.args.why) || c.tool)); nodes.push(w); });
      if (!nodes.length) nodes.push(plain(e.chat ? 'Writing the answer…' : 'Writing the conclusion…'));
      return row(e, box('think', `${mdl(e.model)} · step ${e.step}${e.reasoning ? ' · reasoning summary' : ''}`, nodes));
    }
    case 'sre.rca.tool': {
      const args = Object.entries(e.args || {}).filter(([k]) => k !== 'why').map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(', ');
      return row(e, details(`${e.ok ? '✓' : '✕'} ${e.tool}(${args}) → ${e.summary}`, e.preview));
    }
    case 'sre.case.escalated_model': return row(e, box('act', 'escalation', [`First answer was weak (${e.reason}); re-investigating the same evidence with ${e.to_model}.`]));
    case 'sre.case.investigated': {
      renderBrief(e, null);
      const tok = (Number(e.input_tokens) || 0) + (Number(e.output_tokens) || 0) + (Number(e.cache_read_tokens) || 0);
      const n = Object.values(calls).reduce((a, b) => a + b, 0);
      return row(e, box('done', 'brief submitted', [`Done: ${n} MCP calls (Observability Cloud ${calls['o11y-mcp-gateway']}, Splunk ${calls['splunk-mcp-server'] + calls['splunk-rest']}), ${tok.toLocaleString()} LLM tokens, $${Number(e.cost_usd || 0).toFixed(4)}, ${e.seconds}s · ${mdl(e.model)}`]));
    }
    case 'remediation.proposed': renderAction(e); return row(e, plain(`Proposed ${e.action} — policy: ${e.requirement}. See the brief →`));
    case 'approval.decided': status(`${e.decision === 'approve' ? 'Approved' : 'Rejected'} by ${e.approver}`); return row(e, plain(`${e.decision === 'approve' ? 'Approved' : 'Rejected'} by ${e.approver}`));
    case 'remediation.executing': status('Executor re-checking state, then acting…'); return row(e, plain('Executor re-checking state, then acting…'));
    case 'remediation.refused': status('Executor refused: ' + e.reason, 'bad'); return row(e, box('err', 'executor', ['Refused: ' + e.reason]));
    case 'remediation.state': return row(e, plain(`State before ${JSON.stringify(e.pre_state)} → after ${JSON.stringify(e.post_state)}`));
    case 'remediation.executed': status(`Action ${e.executed ? 'executed' : 'NOT executed'}`, e.executed ? '' : 'bad'); return row(e, plain(`Action ${e.executed ? 'executed' : 'NOT executed'}`));
    case 'remediation.verified': status(e.outcome_ok ? `Verified by the fixed query (last value ${e.value})` : `Not verified (last value ${e.value}); escalated to a human`, e.outcome_ok ? 'good' : 'bad');
      return row(e, box(e.outcome_ok ? 'done' : 'err', 'verification', [e.outcome_ok ? `Verified (last value ${e.value}).` : `Not verified (last value ${e.value}).`]));
    case 'sre.case.mitigated_awaiting_clear': status('Mitigated — waiting for the detector to clear on its own', 'good'); return row(e, plain('Mitigated — waiting for the detector to clear.'));
    case 'sre.case.escalated': if (!briefShown) renderEnd('Escalated to a human: no answer', [].concat(e.reason || 'escalated').join('; ')); status('Escalated to a human: ' + [].concat(e.reason || '').join('; '), 'bad'); return row(e, box('err', 'escalated', [[].concat(e.reason || 'escalated to a human').join('; ')]));
    case 'sre.audit.write_failed': return row(e, box('err', 'audit', [`Audit record ${e.lost_event} did not reach index ${e.index}: ${e.error} (${e.failures_total} lost so far)`]));
    case 'sre.case.inconclusive': if (!briefShown) renderEnd('Inconclusive: no answer', [].concat(e.reason || 'the investigation did not reach a conclusion').join('; '));
      return row(e, box('act', null, ['Inconclusive: the evidence above is for a human.']));
    case 'sre.case.stop_requested': return row(e, plain(`Stop requested by ${e.by}: waiting for the current call to return…`));
    case 'sre.case.stopped': setRunning(false);
      renderEnd('Stopped by the operator', `Stopped by ${e.by} during ${e.stage}, after ${e.model_calls} model call(s), $${Number(e.cost_usd || 0).toFixed(4)} spent. Nothing was proposed or executed.`, 'closed');
      return row(e, box('err', 'stopped', [`Stopped by ${e.by} during ${e.stage}. ${e.model_calls} model call(s), $${Number(e.cost_usd || 0).toFixed(4)} spent; nothing proposed or executed.`]));
    case 'sre.case.escalation_failed': return row(e, box('act', 'escalation failed', [`The re-run with ${mdl(e.to_model)} failed (${e.error}). Keeping the first answer from ${mdl(e.kept_model)}.`]));
    case 'sre.llm.retry': return row(e, plain(`The model API refused the request (${e.error}); retrying once in ${e.after_s}s…`));
    case 'sre.case.closed': return row(e, plain(`Case closed${e.reason ? ': ' + String(e.reason).slice(0, 160) : ''}`));
    case 'sre.case.paged': status(`Paged ${e.team} (simulated)`); return row(e, box('act', 'page', [`${e.by} paged ${e.team}. ${e.note}`]));
    case 'sre.case.acknowledged': return row(e, plain(`Acknowledged by ${e.by}: ${e.note}`));
    case 'sre.case.rerun_requested': return row(e, plain(`Re-run requested by ${e.by} — a new case was opened`));
    case 'sre.chat.question': setRunning(true); return row(e, box('user', e.by, [e.question]));
    case 'sre.chat.done': setRunning(false); return;
    case 'sre.chat.answer': return row(e, box('done', `${mdl(e.model)} · $${Number(e.cost_usd || 0).toFixed(4)}`, [rich(e.answer)]));
    case 'sre.console.error': return row(e, box('err', 'error', [e.error]));
    case 'sre.console.done': setRunning(false); loadSide();
      if (!briefShown && e.state && e.state !== 'investigating') renderEnd(`Case ended: ${String(e.state).replace(/_/g, ' ')}`, 'The investigation ended without a brief; the reasoning pane shows how far it got.');
      return;
    case 'sre.console.history': return renderHistory(e);
  }
}

function list(label, items, fill) { if (!(items || []).length) return null; const w = el('div'); w.append(el('div', 'lab', label)); const ul = el('ul'); items.forEach(x => { const li = el('li'); fill(li, x); ul.append(li); }); w.append(ul); return w; }
function renderEnd(title, reason, state) {   // the case ended without an investigation result: say so instead of "Investigating…"
  briefShown = true; const b = $('#brief'); b.replaceChildren();
  b.append(el('span', 'cat', 'NO BRIEF'), el('h3', null, title));
  const r = el('div', null, reason); r.style.color = 'var(--warn)'; b.append(r);
  b.append(plain('The evidence collected so far is in the reasoning pane. Re-run the RCA (root cause analysis) for a fresh investigation, or page the owning team.'));
  b.append(caseActions(current, null, { state }));
  const st = el('div', 'lab'); st.id = 'execstatus'; b.append(st);
}
function renderBrief(e, pageTeam) {
  briefShown = true; const b = $('#brief'); b.replaceChildren();
  mergeBanners(e).forEach(x => b.append(x));
  b.append(el('span', 'cat', CATEGORY[e.failure_mode] || 'UNDETERMINED'));
  b.append(el('h3', null, e.summary || `${e.root_cause_service} · ${String(e.failure_mode || '').replace(/_/g, ' ')}`));
  const kv = el('div', 'kv'); const add = (k, v) => { if (v) kv.append(el('div', 'k', k), typeof v === 'string' ? el('div', null, v) : v); };
  add('Customer impact', e.impact); add('Root cause', `${e.root_cause_service} · ${String(e.failure_mode || '').replace(/_/g, ' ')} (confidence ${e.confidence})`);
  add('Started', e.started_at); add('Page team', e.page_team || pageTeam); add('Trigger', (e.detectors || []).map(short).join(' + '));
  add('Grouped', groupedNode(e.incidents_joined));
  add('Check next', ((e.topology || {}).check_next || []).slice(0, 3).map(x => `${x.service} (${x.path.join(' → ')}), silent`).join('; '));
  b.append(kv);
  const tslot = el('div'); b.append(tslot); if (e.case_id) loadTies(e.case_id, tslot);
  const slot = el('div'); slot.id = 'actionslot'; b.append(slot);
  const pa = (e.proposed_action && e.proposed_action.type) || e.proposed_action || 'inconclusive';
  renderAction({ case_id: e.case_id, action: pa, requirement: pa === 'no_action' ? 'none' : pa === 'inconclusive' ? 'none' : 'pending', tier: '–' }, true);
  b.append(caseActions(e.case_id, e.page_team || pageTeam, e));
  const st = el('div', 'lab'); st.id = 'execstatus'; b.append(st);
  if ((e.cause_chain || []).length) { b.append(el('div', 'lab', 'Cause chain (root cause → alert)')); const ol = el('ol'); e.cause_chain.forEach(x => ol.append(el('li', null, x))); b.append(ol); }
  if (e.tree_text) { b.append(el('div', 'lab', 'Hypothesis tree (parallel sub-agents, verdicts checked by code)')); const tp = el('pre', null, e.tree_text); tp.style.whiteSpace = 'pre'; tp.style.overflowX = 'auto'; b.append(tp); }
  const ev = list('Evidence', e.evidence, (li, v) => li.append(el('span', 'chip ' + v.signal, v.signal), document.createTextNode(v.finding)));
  if (ev) b.append(ev); else { const hy = list('Hypotheses', e.hypotheses, (li, h) => li.append(el('span', 'chip ' + (h.status || ''), h.status || '?'), document.createTextNode(h.statement))); if (hy) b.append(hy); }
  const ro = list('Ruled out', e.ruled_out, (li, x) => li.append(document.createTextNode(x))); if (ro) b.append(ro);
  if (e.evidence_gap) { const g = el('div', null, 'Evidence gap: ' + e.evidence_gap); g.style.color = 'var(--warn)'; b.append(g); }
  if (e.escalation_error) { const g = el('div', null, 'Escalation: ' + e.escalation_error); g.style.color = 'var(--warn)'; b.append(g); }
  if (e.narrative) b.append(details('Full narrative', e.narrative));
}
let toastTimer = null;
function toast(text, bad) { const t = $('#toast'); t.textContent = text; t.className = 'show' + (bad ? ' bad' : ''); clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.className = bad ? 'bad' : ''; }, bad ? 7000 : 3500); }
function modal({ title, body, ok = 'OK', danger = false, reasons = null }) {   // in-page dialog; resolves to the reason text, true, or null (cancel)
  return new Promise(resolve => {
    const d = el('dialog', 'modal'); d.append(el('h4', null, title));
    (Array.isArray(body) ? body : [body]).forEach(x => { if (x) d.append(typeof x === 'string' ? el('p', 'msg', x) : x); });
    let ta = null;
    if (reasons) {
      d.append(el('label', null, 'Reason (kept in the audit trail)'));
      const q = el('div', 'quick');
      reasons.forEach(r => { const b = el('button', null, r); b.type = 'button'; b.onclick = () => { ta.value = r; q.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); ta.focus(); }; q.append(b); });
      ta = el('textarea'); ta.placeholder = 'Why is this case being closed?'; d.append(q, ta);
    }
    const foot = el('div', 'foot'); const no = el('button', 'reject', 'Cancel'); const yes = el('button', 'go' + (danger ? ' danger' : ''), ok);
    no.type = yes.type = 'button'; foot.append(no, yes); d.append(foot);
    const done = (v) => { d.close(); d.remove(); resolve(v); };
    no.onclick = () => done(null); d.addEventListener('cancel', (ev) => { ev.preventDefault(); done(null); });
    yes.onclick = () => { if (ta && !ta.value.trim()) { ta.focus(); ta.style.borderColor = 'var(--warn)'; return; } done(ta ? ta.value.trim() : true); };
    if (ta) ta.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.metaKey || ev.ctrlKey)) yes.click(); });
    document.body.append(d); d.showModal(); (ta || yes).focus();
  });
}
const CLOSE_REASONS = ['stale alert', 'false positive', 'duplicate of another case', 'fixed outside the agent', 'demo / test case'];
async function closeCase(cid, btn) {
  const msg = el('p', 'msg'); msg.append('Case ', el('b', null, cid), ' will be closed. If it has a proposed action waiting for approval, that action is rejected and recorded as rejected.');
  const reason = await modal({ title: 'Close case', body: msg, ok: 'Close case', danger: true, reasons: CLOSE_REASONS });
  if (reason === null) return;
  if (btn) btn.disabled = true;
  const r = await api('/api/close', { case_id: cid, reason });
  if (r.error) { toast(r.error, true); if (btn) btn.disabled = false; return; }
  toast(`Case ${cid} closed: ${reason}`); if (cid === current) status(`Case closed (${reason})`); loadSide();
}
async function confirmRerun(what) {
  return modal({ title: 'Re-run the investigation', body: [`A fresh investigation of ${what} starts now; the earlier case stays as it is.`, 'It uses the model (typically $0.05–0.40) and takes about a minute.'], ok: 'Re-run RCA' });
}
const CLOSABLE = ['proposed', 'awaiting_approval', 'inconclusive', 'escalated', 'verification_failed', 'mitigated_awaiting_clear', 'resolved'];
function caseActions(cid, team, e) {
  const w = el('div', 'btns'); w.style.flexWrap = 'wrap';
  const mk = (label, cls, fn) => { const x = el('button', cls, label); x.onclick = () => fn(x); w.append(x); return x; };
  mk(`Page ${team || 'on-call'}`, 'reject', (x) => { x.disabled = true; api('/api/page', { case_id: cid }).then(r => { status(r.ok ? `Paged ${r.team} (simulated — no paging integration connected; recorded in the audit trail)` : r.error); }); });
  if (!e || e.state !== 'closed') mk('Close case', 'reject', (x) => closeCase(cid, x));
  mk('Re-run RCA', 'reject', async (x) => { if (!(await confirmRerun('this alert'))) return; x.disabled = true;
    api('/api/rerun', { case_id: cid }).then(r => { if (r.case_id) { open(r.case_id); loadSide(); } else { x.disabled = false; toast(r.error, true); } }); });
  mk('Copy brief', 'reject', () => { const txt = $('#brief').innerText; (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(() => status('Brief copied'), () => status('Copy not available in this browser')); });
  const box = el('div'); box.append(el('div', 'lab', 'Actions'), w); return box;
}
function renderAction(e, placeholder) {
  const slot = $('#actionslot'); if (!slot) return; slot.replaceChildren();
  const a = el('div', 'action');
  if (placeholder) {
    if (e.action === 'no_action') { a.append(el('b', null, 'Recommended action: none — nothing to change in the platform')); a.append(plain('Use the actions below: page the owning team, acknowledge and close, or re-run the RCA (root cause analysis).')); }
    else if (e.action === 'inconclusive') { a.append(el('b', null, 'Inconclusive: no action proposed')); a.append(plain('The evidence is in the reasoning pane. Page the owning team or re-run the RCA.')); }
    else { a.append(el('b', null, `Proposed: ${e.action}`)); a.append(plain('Waiting for the policy decision…')); }
    slot.append(a); return;
  }
  a.append(el('b', null, e.action === 'no_action' ? 'Recommended action: none — notify and close' : `Recommended action: ${e.real_world || e.action}`));
  a.append(plain(`${e.action} · policy: ${e.requirement === 'ask' ? 'a human must approve' : e.requirement} (tier ${e.tier})`));
  if (e.verification) a.append(plain('Verified by: ' + e.verification));
  if ([].concat(e.reasons || []).length) a.append(plain('Policy: ' + [].concat(e.reasons).join('; ')));
  if (e.request && Object.keys(e.request).length && e.action !== 'no_action') a.append(details('Exact request the executor will send', JSON.stringify(e.request, null, 1)));
  if (e.jev) a.append(plain(`Jev advisory check: ${e.jev}${e.jev_mode && e.jev_mode !== 'real' ? ' (' + e.jev_mode + ' mode)' : ''}`));
  if (e.requirement === 'ask') {
    const bt = el('div', 'btns'); const ok = el('button', 'approve', 'Approve'); const no = el('button', 'reject', 'Reject');
    ok.onclick = () => { ok.disabled = no.disabled = true; api('/api/approve', { case_id: e.case_id, plan_hash: e.plan_hash }); };
    no.onclick = () => { ok.disabled = no.disabled = true; api('/api/reject', { case_id: e.case_id, reason: 'rejected in the console' }).then(() => { status('Rejected'); loadSide(); }); };
    bt.append(ok, no); a.append(bt);
  }
  slot.append(a);
}
function status(text, cls) { const s = $('#execstatus'); if (!s) return; s.textContent = text; s.style.color = cls === 'bad' ? 'var(--bad)' : cls === 'good' ? 'var(--good)' : 'var(--muted)'; }
function renderHistory(h) {
  const c = h.case; row({ t: Date.parse(c.opened_at) / 1000 }, plain(`Case ${c.id} ran before this console session; showing its stored result. Live steps appear for cases started here.`));
  renderStored(c, h.page_team);
}
// events that change a case after its brief was drawn: redraw the brief from the stored case (no page reload)
const REFRESH_ON = new Set(['sre.case.merged', 'sre.case.merged_away', 'sre.case.incident_added', 'sre.case.incident_attached', 'sre.case.tie_dismissed',
  'sre.case.tie_suggested', 'sre.case.closed', 'sre.case.closed_by_operator', 'sre.case.mitigated_awaiting_clear', 'sre.case.resolved', 'sre.case.verification_failed']);
let refreshTimer = null;
function refreshSoon(cid) { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => { refreshCase(cid); loadSide(); }, 300); }
async function refreshCase(cid) {
  if (!cid || cid !== current) return;
  const c = await api(`/api/case/${encodeURIComponent(cid)}`);
  if (c.error || cid !== current || ['open', 'investigating'].includes(c.state)) return;   // a running investigation draws its own brief
  renderStored(c, c.page_team);
}
function renderStored(c, pageTeam) {
  const inv = c.investigation;
  if (!inv) { const last = (c.history || []).slice(-1)[0] || {}; if (!['open', 'investigating'].includes(c.state)) renderEnd(`Case ${String(c.state).replace(/_/g, ' ')}`, [].concat(last.reason || 'no investigation result was stored').join('; '), c.state); return; }
  renderBrief(Object.assign({}, inv, { case_id: c.id, state: c.state, detectors: (c.incidents || []).map(i => i.detector), ties: Object.values(c.ties || {}), topology: c.topology, merged_into: c.merged_into, merged_by: c.merged_by, merged_at: c.merged_at,
    unreviewed_alerts: c.unreviewed_alerts !== undefined ? c.unreviewed_alerts : (c.investigation ? (c.incidents || []).filter(i => i.joined && ['merged', 'added'].includes(i.joined.rule)).map(i => i.detector) : []),
    incidents_joined: (c.incidents || []).filter(i => i.joined).map(i => Object.assign({ detector: i.detector }, i.joined)) }), pageTeam);
  const d = c.decision; if (d && d.action) renderAction({ case_id: c.id, action: d.action, real_world: d.real_world, requirement: c.state === 'awaiting_approval' ? d.requirement : `none (${String(c.state).replace(/_/g, ' ')})`,
    tier: d.tier, reasons: d.reasons, verification: (d.verification || {}).description, request: d.request_preview, jev: (d.jev || {}).verdict, jev_mode: (d.jev || {}).mode, plan_hash: d.plan_hash });
}
function open(cid) {
  current = cid; t0 = null; calls = freshCalls(); briefShown = false; setRunning(false);
  $('#trace').replaceChildren(); $('#brief').replaceChildren(el('div', 'empty', 'Investigating… the brief appears when the investigation concludes.'));
  $('#q').disabled = false; $('#q').placeholder = `Follow-up about ${cid}… e.g. “why not a config change?”`;
  if (es) es.close(); es = new EventSource(`/api/stream/${encodeURIComponent(cid)}?t=${encodeURIComponent(TOKEN)}`);
  es.onmessage = (m) => { try { render(JSON.parse(m.data)); } catch (x) { console.error(x); } };
  document.querySelectorAll('#cases .item').forEach(n => n.classList.toggle('on', n.dataset.cid === cid));
}
async function start(body) { const r = await api('/api/investigate', body); if (r.case_id) { open(r.case_id); loadSide(); } else toast(r.error || 'could not start', true); }

function tile(label, value, sub, cls) { const t = el('div', 'tile'); t.append(el('div', 'l', label), el('div', 'v' + (cls ? ' ' + cls : ''), value), el('div', 's', sub || '')); return t; }
async function loadStatus() {
  const r = await api('/api/status'); const s = r.status || {}; const st = $('#strip'); st.replaceChildren();
  if (!r.status) { st.append(tile('Status', '…', r.error ? 'error: ' + r.error : 'loading (refreshes every 30 s)')); return; }
  st.append(tile('Approval rate · 5 min', s.approval_pct == null ? '–' : s.approval_pct + '%', `${(s.payments_5m || 0).toLocaleString()} payments`, s.approval_pct == null ? '' : s.approval_pct < 85 ? 'bad' : s.approval_pct < 90 ? 'warn' : 'good'));
  st.append(tile('checkout-api p90', (s.checkout_p90_ms || 0) + ' ms', 'APM, last 5 min', s.checkout_p90_ms > 1500 ? 'bad' : s.checkout_p90_ms > 1000 ? 'warn' : 'good'));
  st.append(tile('payment-router errors', (s.router_error_pct || 0) + '%', 'APM, last 5 min', s.router_error_pct > 5 ? 'bad' : s.router_error_pct > 1 ? 'warn' : 'good'));
  st.append(tile('Open alerts', String(r.open_alerts), (s.unhealthy || []).length ? 'unhealthy: ' + s.unhealthy.join(', ') : 'all services Ok', r.open_alerts ? 'warn' : 'good'));
  const f = tile('Faults injected (war room)', String((s.faults_on || []).length), '', (s.faults_on || []).length ? 'bad' : 'good');
  const sub = f.querySelector('.s'); (s.faults_on || []).forEach(x => sub.append(el('span', 'fchip', x))); (s.load_on || []).forEach(x => sub.append(el('span', 'fchip load', x)));
  if (s.faults_on == null) sub.textContent = 'war-room panel not reachable';
  st.append(f);
}
function clearCtl(what, hidden, nothingShown) {   // Clear hides finished items (nothing deleted); Show brings them back
  const w = $(`#clr-${what}`); if (!w) return; w.replaceChildren();
  if (hidden) { const sh = el('button', 'link', `Show ${hidden} hidden`); sh.onclick = async () => { await api('/api/unclear', { what }); loadSide(); }; w.append(sh); }
  if (!nothingShown) { const cl = el('button', null, 'Clear'); cl.title = what === 'cases' ? 'Hide finished cases (awaiting approval and running cases stay)' : 'Hide the alerts open now; a new firing shows again';
    cl.onclick = async () => { await api('/api/clear', { what }); toast(what === 'cases' ? 'Finished cases hidden' : 'Current alerts hidden'); loadSide(); }; w.append(cl); }
}
async function loadSide() {
  try {
    api('/api/cases').then(cs => {
      $('#mode').textContent = `model: ${cs.settings.provider === 'mock' ? 'scripted mock (no AI)' : cs.settings.provider} · policy: ${cs.settings.policy}`;
      const c = $('#cases'); c.replaceChildren(); clearCtl('cases', cs.hidden || 0, !(cs.cases || []).length);
      (cs.cases || []).forEach(x => { const it = el('div', 'item'); it.dataset.cid = x.id; it.classList.toggle('on', x.id === current);
        it.append(el('span', 't', `${x.id} · ${String(x.state).replace(/_/g, ' ')}`), el('span', 's', `${(x.detectors || []).map(short).join(' + ')}${x.action ? ' → ' + x.action : ''}`));
        // merged cases in amber, like the merge banner in the brief; each card names both ends of the merge
        if (x.merged_into) { it.classList.add('merged'); const t = el('span', 'tag warn', `MERGED: ${x.id} → ${x.merged_into}`); t.title = `Open ${x.merged_into}`;
          t.onclick = (ev) => { ev.stopPropagation(); open(x.merged_into); }; const w = el('div'); w.append(t); it.append(w); }
        [...new Set(x.merged_from || [])].forEach(src => { it.classList.add('merged'); const t = el('span', 'tag warn', `MERGED: ${src} → ${x.id}`); t.title = `Open ${src}`;
          t.onclick = (ev) => { ev.stopPropagation(); open(src); }; const w = el('div'); w.append(t); it.append(w); });
        if (CLOSABLE.includes(x.state)) { const cb = el('button', null, 'Close case'); cb.onclick = (ev) => { ev.stopPropagation(); closeCase(x.id, cb); }; it.append(cb); }
        it.onclick = () => open(x.id); c.append(it); });
    });
    const inc = await api('/api/incidents'); const a = $('#alerts'); a.replaceChildren(); clearCtl('alerts', inc.hidden || 0, !(inc.incidents || []).length);
    if (inc.error && !inc.incidents) { a.append(el('div', 'item', 'Could not read incidents: ' + inc.error)); return; }
    if (!(inc.incidents || []).length) a.append(el('div', 'item', inc.hidden ? `No new alerts (${inc.hidden} cleared, still firing).` : 'No TukTukPay detector is firing. Ask a question above, or start an act from the war-room panel.'));
    (inc.incidents || []).forEach(i => {
      const it = el('div', 'item'); it.append(el('span', 't', short(i.detector)), el('span', 's', `${i.severity} · since ${String(i.since || '').replace('T', ' ').slice(0, 16)} UTC`));
      if (i.case_id) {
        it.append(el('span', 's', `case ${i.case_id} · ${String(i.case_state || '').replace(/_/g, ' ')}`));
        const btns = el('div'); btns.style.display = 'flex'; btns.style.gap = '6px'; btns.style.flexWrap = 'wrap';
        const b = el('button', null, 'Open case'); b.onclick = (ev) => { ev.stopPropagation(); open(i.case_id); }; btns.append(b);
        if (!['open', 'investigating', 'remediating', 'verifying'].includes(i.case_state)) {   // the alert is still firing: investigate it again
          const rr = el('button', null, 'Re-run RCA'); rr.onclick = async (ev) => { ev.stopPropagation(); if (!(await confirmRerun(`“${short(i.detector)}”`))) return;
            rr.disabled = true; start({ incident_id: i.incident_id, rerun: true }).finally(() => { rr.disabled = false; }); }; btns.append(rr);
        }
        if (CLOSABLE.includes(i.case_state)) { const cb = el('button', null, 'Close case'); cb.onclick = (ev) => { ev.stopPropagation(); closeCase(i.case_id, cb); }; btns.append(cb); }
        it.append(btns);
        it.onclick = () => open(i.case_id);
      } else {
        const b = el('button', null, 'Triage'); b.onclick = (ev) => { ev.stopPropagation(); b.disabled = true; start({ incident_id: i.incident_id }).finally(() => { b.disabled = false; }); };
        it.append(b);
      }
      a.append(it);
    });
  } catch (x) { $('#alerts').replaceChildren(el('div', 'item', 'Could not load alerts and cases: ' + (x && x.message || x))); }
}
PRESETS.forEach(([label, q]) => { const b = el('button', null, label); b.type = 'button'; b.onclick = () => { $('#symptom').value = q; $('#symptom').focus(); }; $('#chips').append(b); });
$('#askform').onsubmit = (ev) => { ev.preventDefault(); const q = $('#symptom').value.trim(); if (q) start({ question: q }); };
$('#follow').onsubmit = (ev) => { ev.preventDefault(); const q = $('#q').value.trim(); if (!q || !current) return; $('#q').value = '';
  api('/api/ask', { case_id: current, question: q }).then(r => { if (r.error) toast(r.error, true); else if (r.case_id) { open(r.case_id); loadSide(); } }); };
$('#stop').onclick = () => { if (!current) return; const b = $('#stop'); b.disabled = true; b.textContent = 'Stopping…';
  api('/api/stop', { case_id: current }).then(r => { if (r.error) { toast(r.error, true); b.disabled = false; b.textContent = 'Stop'; } }); };
loadSide(); loadStatus(); setInterval(loadSide, 10000); setInterval(loadStatus, 30000);
const pre = new URLSearchParams(location.search).get('case'); if (pre) open(pre);
</script></body></html>"""


def page(token: str) -> str:
    return PAGE.replace("__TOKEN__", html.escape(token, quote=True))
