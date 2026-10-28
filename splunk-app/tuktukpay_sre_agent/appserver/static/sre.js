/* TukTukPay SRE Agent 1.1 — investigations of our SRE agent (services/sre-agent, run in the AI Toolkit container),
   read live from index=tuktukpay_agent_audit through the logged-in Splunk session.
   Layout follows the patterns common to AI SRE products (conclusion first; hypotheses as Checked → Evidence → Result;
   ruled-out branches kept visible; evidence that opens its source; live step trace) and shows what is ours:
   the sub-agent's verdict next to the code's decision, cost and tokens per case, and the data path.
   All model text is untrusted: inserted as text only, never as HTML. */
(function () {
  'use strict';
  const ROOT = '/' + (location.pathname.split('/')[1] || 'en-US') + '/splunkd/__raw';
  const WEB = '/' + (location.pathname.split('/')[1] || 'en-US');
  const IDX = 'index=tuktukpay_agent_audit';
  const O11Y = 'https://app.us1.signalfx.com/#/apm';
  const ORG = 'YOUR_ORG_ID', ENV = 'tuktukpay-demo';
  const RANGES = { '4h': '-4h', '24h': '-24h', '7d': '-7d' };
  const S = { range: '24h', cases: [], states: {}, sources: {}, selected: null, tab: 'tree', showRuledOut: true };
  const STATUS = {
    validated: { icon: 'check', cls: 'is-ok', label: 'Validated' },
    invalidated: { icon: 'x', cls: 'is-bad', label: 'Ruled out' },
    inconclusive: { icon: 'q', cls: 'is-warn', label: 'Inconclusive' },
    'not tested': { icon: 'minus', cls: 'is-muted', label: 'Not tested' },
    open: { icon: 'pending', cls: 'is-muted', label: 'Running' },
  };
  const STATE_ORDER = ['opened', 'investigating', 'proposed', 'awaiting_approval', 'approved', 'remediating', 'executed', 'resolved',
                       'rejected', 'stopped', 'escalated', 'closed'];
  const STATE_LABEL = { awaiting_approval: 'Awaiting approval', proposed: 'Proposed', investigating: 'Investigating', executed: 'Executed',
                        resolved: 'Resolved', rejected: 'Rejected', stopped: 'Stopped', escalated: 'Escalated', closed: 'Closed', opened: 'Opened' };

  // ---------- helpers ----------
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = String(text); return e; }
  function chip(text, cls) { return el('span', 'sre-chip ' + (cls || ''), text); }
  function link(text, href) { const a = el('a', 'sre-link'); a.append(document.createTextNode(text), icon('external')); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; return a; }

  // ---------- icons: inline SVG, stroke = currentColor (24×24 grid, 2px strokes) ----------
  const ICONS = {
    check: [['path', { d: 'M20 6 9 17l-5-5' }]],
    x: [['path', { d: 'M18 6 6 18M6 6l12 12' }]],
    help: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M9.5 9.2a2.6 2.6 0 0 1 5 .9c0 1.7-2.5 2.3-2.5 3.6' }], ['path', { d: 'M12 17h.01' }]],
    pending: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3 2' }]],
    q: [['path', { d: 'M9 9.2a3 3 0 0 1 5.8 1.1c0 2-3 2.6-3 4.2' }], ['path', { d: 'M12 18.5h.01' }]],
    minus: [['path', { d: 'M7 12h10' }]],
    bang: [['path', { d: 'M12 6v8' }], ['path', { d: 'M12 18.5h.01' }]],
    skip: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M8 12h8' }]],
    alert: [['path', { d: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z' }], ['path', { d: 'M12 9v4M12 17h.01' }]],
    branch: [['circle', { cx: 6, cy: 6, r: 2.5 }], ['circle', { cx: 6, cy: 18, r: 2.5 }], ['circle', { cx: 18, cy: 8, r: 2.5 }], ['path', { d: 'M6 8.5v7M18 10.5c0 4-4 5-9.5 6' }]],
    gantt: [['path', { d: 'M3 4v16h18' }], ['path', { d: 'M7 8h7M10 12h8M8 16h5' }]],
    evidence: [['path', { d: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z' }], ['path', { d: 'M14 3v6h6' }], ['circle', { cx: 11, cy: 14, r: 2.5 }], ['path', { d: 'm13 16 2 2' }]],
    terminal: [['path', { d: 'm4 17 6-5-6-5M12 19h8' }]],
    book: [['path', { d: 'M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z' }], ['path', { d: 'M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5' }]],
    clock: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3 2' }]],
    coin: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M14.5 9.2c-.5-.8-1.4-1.2-2.5-1.2-1.5 0-2.6.8-2.6 2s1.1 1.7 2.6 2 2.6.8 2.6 2-1.1 2-2.6 2c-1.2 0-2.2-.5-2.6-1.3M12 6.5V8M12 16v1.5' }]],
    shield: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }], ['path', { d: 'M9 12l2 2 4-4' }]],
    activity: [['path', { d: 'M22 12h-4l-3 9L9 3l-3 9H2' }]],
    target: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 5 }], ['circle', { cx: 12, cy: 12, r: 1.5 }]],
    chip: [['rect', { x: 6, y: 6, width: 12, height: 12, rx: 2 }], ['path', { d: 'M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4' }]],
    tool: [['path', { d: 'M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z' }]],
    tokens: [['path', { d: 'M4 7h16M4 12h16M4 17h10' }]],
    users: [['circle', { cx: 9, cy: 8, r: 3.5 }], ['path', { d: 'M2.5 20c.8-3.5 3.4-5.5 6.5-5.5s5.7 2 6.5 5.5' }], ['path', { d: 'M16 4.5a3.5 3.5 0 0 1 0 7M18.5 14.8c1.6.8 2.6 2.6 3 5.2' }]],
    external: [['path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' }], ['path', { d: 'M15 3h6v6M10 14 21 3' }]],
    refresh: [['path', { d: 'M21 4v6h-6' }], ['path', { d: 'M20.5 15A9 9 0 1 1 18.4 5.6L21 10' }]],
    database: [['ellipse', { cx: 12, cy: 5, rx: 8, ry: 3 }], ['path', { d: 'M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3' }]],
    hourglass: [['path', { d: 'M6 2h12M6 22h12M7 2c0 5 10 5 10 10S7 17 7 22M17 2c0 5-10 5-10 10s10 5 10 10' }]],
  };
  function icon(name, cls, size) {
    // explicit size and paint on every shape: Splunk's own CSS can restyle bare svg/path elements
    const NS = 'http://www.w3.org/2000/svg', px = String(size || 14);
    const s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', px); s.setAttribute('height', px);
    s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
    s.setAttribute('class', 'sre-ic' + (cls ? ' ' + cls : ''));
    s.style.width = px + 'px'; s.style.height = px + 'px';
    (ICONS[name] || ICONS.help).forEach(([tag, attrs]) => {
      const n = document.createElementNS(NS, tag);
      Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
      n.setAttribute('fill', 'none'); n.setAttribute('stroke', 'currentColor'); n.setAttribute('stroke-width', '2');
      n.setAttribute('stroke-linecap', 'round'); n.setAttribute('stroke-linejoin', 'round');
      s.append(n);
    });
    return s;
  }
  function ichip(name, text, cls) { const c = el('span', 'sre-chip ' + (cls || '')); c.append(icon(name, null, 12), document.createTextNode(text)); return c; }
  function csrf() { const m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/); return m ? decodeURIComponent(m[1]) : ''; }
  function fmtTime(t) { return new Date(t * 1000).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }); }
  function fmtClock(t) { return new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  function short(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function money(v) { const n = Number(v); return isFinite(n) ? '$' + n.toFixed(2) : '–'; }
  function num(v) { const n = Number(v); return isFinite(n) ? n.toLocaleString() : '–'; }
  function safeCase(id) { return /^C-[0-9A-Za-z-]{4,40}$/.test(id || '') ? id : null; }
  function cleanDet(d) { return String(d || '').replace(/TukTukPay \[tuktukpay-demo\] /g, '').replace(/^ML anomaly: /, 'ML anomaly · '); }
  function isTree(c) { return /sub-agents/.test(c.model || '') || !!c.tree_text; }
  function niceAction(a) { return String(a || 'inconclusive').replace(/^chaos\.flag_off:/, 'Turn off fault: ').replace(/^k8s\.rollout_undo:/, 'Roll back: ').replace(/_/g, ' '); }

  async function spl(query, earliest) {
    const q = query.trim().startsWith('|') ? query.trim() : 'search ' + query.trim();
    const body = new URLSearchParams({ search: q, exec_mode: 'oneshot', output_mode: 'json', count: '0', earliest_time: earliest, latest_time: 'now' });
    const res = await fetch(ROOT + '/services/search/jobs', { method: 'POST', body, credentials: 'same-origin',
      headers: { 'X-Splunk-Form-Key': csrf(), 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/x-www-form-urlencoded' } });
    if (!res.ok) throw new Error('search HTTP ' + res.status);
    const d = await res.json();
    const err = (d.messages || []).find(m => m.type === 'FATAL' || m.type === 'ERROR');
    if (err) throw new Error(err.text);
    return d.results || [];
  }
  function parseRaw(rows) { const out = []; rows.forEach(r => { try { out.push(JSON.parse(r._raw)); } catch (e) { /* skip */ } }); return out; }

  // ---------- data ----------
  async function loadCases() {
    const earliest = RANGES[S.range];
    const [inv, st, src] = await Promise.all([
      spl(`${IDX} event=sre.case.investigated | sort - _time | head 200 | table _raw`, earliest),
      spl(`${IDX} event="sre.case.*" event!=sre.case.investigated | stats values(event) as evs by case_id`, earliest),
      spl(`${IDX} event=sre.case.opened | spath output=src path=source | stats latest(src) as src by case_id`, earliest),
    ]);
    S.cases = parseRaw(inv);
    S.states = {};
    st.forEach(r => {
      const evs = [].concat(r.evs || []).map(e => String(e).replace('sre.case.', ''));
      S.states[r.case_id] = evs.sort((a, b) => STATE_ORDER.indexOf(b) - STATE_ORDER.indexOf(a))[0] || '';
    });
    S.sources = {}; src.forEach(r => { S.sources[r.case_id] = r.src; });
  }
  async function loadDetail(caseId) {
    const id = safeCase(caseId); if (!id) return [];
    const rows = await spl(`${IDX} case_id="${id}" (event="sre.tree.*" OR event=sre.case.investigating OR event=sre.case.opened OR event=sre.llm.call OR event=sre.rca.tool OR event=sre.rca.step) | table _raw`, '-7d');
    return parseRaw(rows).sort((a, b) => (a.t || 0) - (b.t || 0));
  }

  // ---------- derived ----------
  function confidenceBand(c, nodes) {
    const v = Number(c.confidence || 0);
    const leafOk = nodes.some(n => n.status === 'validated');
    const gap = !!c.evidence_gap;
    const action = String(c.proposed_action || '');
    if (action === 'inconclusive' || c.root_cause_service === 'none' && action !== 'no_action') return { band: 'Low', cls: 'is-bad', basis: 'No root cause supported by the evidence.' };
    if (!gap && v >= 0.85 && (leafOk || !isTree(c))) return { band: 'High', cls: 'is-ok', basis: isTree(c) ? 'Root-cause branch validated by code: a metric or trace signal and a log signal, still active.' : 'Backed by a metric or trace signal and a log signal (checked by code).' };
    if (!gap && v >= 0.6) return { band: 'Medium', cls: 'is-warn', basis: 'Supported, but alternatives were not all ruled out.' };
    return { band: 'Low', cls: 'is-bad', basis: gap ? 'Code check: ' + c.evidence_gap : 'The agent itself reported low confidence.' };
  }
  function toolIndex(events) { const m = {}; events.filter(e => e.event === 'sre.rca.tool').forEach(e => { m[e.id] = e; }); return m; }
  function evidenceLink(evId, tools) {
    const tool = tools[evId];
    if (tool && tool.args) {
      const a = tool.args;
      if (tool.tool === 'spl' && a.query) return link('Open in Splunk', `${WEB}/app/search/search?q=${encodeURIComponent('search index=tuktukpay ' + a.query)}&earliest=${encodeURIComponent(a.window || '-15m')}&latest=now`);
      if (tool.tool === 'trace' && a.trace_id) return link('Open trace', `${O11Y}/traces/${encodeURIComponent(a.trace_id)}?orgId=${ORG}`);
      if (a.service) return link('Open service', `${O11Y}/service?orgId=${ORG}&service=${encodeURIComponent(a.service)}&environments=${ENV}`);
      if (tool.tool === 'spl_template') return el('span', 'sre-evid', 'log template ' + (a.name || ''));
      if (tool.tool === 'metric_series') return el('span', 'sre-evid', 'metric ' + (a.metric || ''));
    }
    return el('span', 'sre-evid', String(evId || '').startsWith('toolu') ? 'tool call' : 'collected evidence: ' + short(evId, 36));
  }
  function buildTree(events, inv) {
    const nodes = {};
    events.filter(e => e.event === 'sre.tree.branch').forEach(e => { nodes[e.node] = Object.assign(nodes[e.node] || {}, { id: e.node, parent: e.parent, depth: e.depth, statement: e.statement, test_plan: e.test_plan, status: 'open' }); });
    events.filter(e => e.event === 'sre.tree.verdict').forEach(e => {
      const n = nodes[e.node] || (nodes[e.node] = { id: e.node, parent: e.parent, depth: e.depth, statement: e.statement });
      Object.assign(n, { status: e.status, model_verdict: e.model_verdict, checks: e.checks || [], component: e.component, last_seen_utc: e.last_seen_utc,
        seconds: e.seconds, end: e.t, start: e.started || (e.t - (e.seconds || 0)), tool_calls: e.tool_calls, finding: e.finding, evidence: e.evidence || [],
        children_proposed: e.children_proposed || [] });
    });
    events.filter(e => e.event === 'sre.rca.tool' && e.node).forEach(e => { const n = nodes[e.node]; if (n) (n.tools = n.tools || []).push(e); });
    let list = Object.values(nodes);
    if (!list.length && (inv.hypotheses || []).length) {
      list = inv.hypotheses.map((h, i) => ({ id: 'H' + (i + 1), parent: null, depth: 1, statement: h.statement, status: h.status || 'inconclusive', checks: [], flat: true }));
    }
    return list.sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));
  }
  function pickRootCause(nodes, inv) {
    const rc = String(inv.root_cause_service || '').toLowerCase();
    const val = nodes.filter(n => n.status === 'validated').sort((a, b) => (b.depth || 0) - (a.depth || 0));
    const hit = val.find(n => rc && String((n.component || '') + ' ' + (n.statement || '')).toLowerCase().includes(rc));
    return (hit || val[0] || {}).id;
  }

  // ---------- layout ----------
  const root = document.getElementById('sre-root');
  root.textContent = '';
  const head = el('header', 'sre-head');
  const title = el('div', 'sre-title');
  title.append(el('div', 'sre-eyebrow', 'TukTukPay · AI Toolkit container agent'), el('h1', null, 'SRE agent investigations'));
  const controls = el('div', 'sre-controls');
  const sel = el('select', 'sre-select'); sel.id = 'sre-range'; sel.setAttribute('aria-label', 'Time range');
  Object.keys(RANGES).forEach(k => { const o = el('option', null, 'Last ' + k); o.value = k; if (k === S.range) o.selected = true; sel.append(o); });
  sel.addEventListener('change', () => { S.range = sel.value; S.selected = null; refresh(true); });
  const btn = el('button', 'sre-btn'); btn.append(icon('refresh'), document.createTextNode('Refresh')); btn.type = 'button'; btn.addEventListener('click', () => refresh(true));
  const stamp = el('span', 'sre-stamp', '');
  controls.append(stamp, sel, btn);
  head.append(title, controls);
  const fleet = el('div', 'sre-fleet');
  const body = el('div', 'sre-body');
  const list = el('nav', 'sre-list'); list.setAttribute('aria-label', 'Investigations');
  const detail = el('main', 'sre-detail');
  body.append(list, detail);
  const foot = el('footer', 'sre-foot');
  foot.append(icon('database'), el('span', null, 'Data path: Splunk + Observability Cloud through MCP → Anthropic API → this Splunk (index tuktukpay_agent_audit). Nothing runs from this page; actions are approved in the agent console.'));
  root.append(head, fleet, body, foot);

  function renderFleet() {
    fleet.textContent = '';
    const cs = S.cases;
    const found = cs.filter(c => c.root_cause_service && c.root_cause_service !== 'none').length;
    const secs = cs.map(c => Number(c.seconds || 0)).sort((a, b) => a - b);
    const med = secs.length ? secs[Math.floor(secs.length / 2)] : 0;
    const cost = cs.reduce((s, c) => s + Number(c.cost_usd || 0), 0);
    const waiting = cs.filter(c => S.states[c.case_id] === 'awaiting_approval').length;
    [['activity', 'Investigations', num(cs.length)], ['target', 'Root cause named', cs.length ? Math.round(100 * found / cs.length) + '%' : '–'],
     ['clock', 'Median time', med ? Math.round(med) + ' s' : '–'], ['coin', 'Model cost', money(cost)], ['shield', 'Awaiting approval', num(waiting)]]
      .forEach(([ic, k, v]) => { const t = el('div', 'sre-kpi'); const i = el('div', 'sre-kpi-ic'); i.append(icon(ic, null, 18)); const tx = el('div'); tx.append(el('div', 'sre-kpi-v', v), el('div', 'sre-kpi-k', k)); t.append(i, tx); fleet.append(t); });
  }

  function renderList() {
    list.textContent = '';
    if (!S.cases.length) { list.append(el('div', 'sre-empty', 'No investigations in this range. They appear when an alert or a search runs the agent: | fit AITKContainer algo=tuktuk_sre …')); return; }
    S.cases.forEach(c => {
      const row = el('button', 'sre-case' + (S.selected === c.case_id ? ' sel' : ''));
      row.type = 'button'; row.setAttribute('aria-current', S.selected === c.case_id ? 'true' : 'false');
      const st = S.states[c.case_id] || '';
      const top = el('div', 'sre-case-top');
      top.append(el('span', 'sre-case-time', fmtTime(c.t)), ichip(isTree(c) ? 'branch' : 'activity', isTree(c) ? 'Tree' : 'Loop', isTree(c) ? 'is-accent-o' : 'is-muted'));
      if (st) top.append(ichip(/awaiting/.test(st) ? 'shield' : /resolved|executed|closed/.test(st) ? 'check' : 'pending', STATE_LABEL[st] || st, /awaiting/.test(st) ? 'is-warn' : /resolved|executed|closed/.test(st) ? 'is-ok' : 'is-muted'));
      const rc = el('div', 'sre-case-rc', c.root_cause_service || 'No root cause');
      const det = el('div', 'sre-case-det', short((c.detectors || []).map(cleanDet).join(' · '), 80));
      const meta = el('div', 'sre-case-meta', `${Math.round(c.seconds || 0)} s · ${money(c.cost_usd)} · ${S.sources[c.case_id] || 'agent'}`);
      row.append(top, rc, det, meta);
      row.addEventListener('click', () => { S.selected = c.case_id; renderList(); showDetail(c); });
      list.append(row);
    });
  }

  // ---------- detail: conclusion card ----------
  function conclusion(c, nodes, events) {
    const card = el('section', 'sre-concl');
    const st = S.states[c.case_id] || '';
    const band = confidenceBand(c, nodes);
    const top = el('div', 'sre-concl-top');
    top.append(ichip(/awaiting/.test(st) ? 'shield' : 'check', STATE_LABEL[st] || 'Investigated', /awaiting/.test(st) ? 'is-warn' : 'is-muted'),
      ichip(band.cls === 'is-ok' ? 'check' : band.cls === 'is-warn' ? 'help' : 'alert', band.band + ' confidence', band.cls),
      ichip(isTree(c) ? 'branch' : 'activity', isTree(c) ? 'Hypothesis tree · parallel sub-agents' : 'Single agent loop', 'is-muted'));
    card.append(top);
    const rl = el('div', 'sre-concl-label'); rl.append(icon('target'), document.createTextNode('Root cause'));
    card.append(rl, el('div', 'sre-concl-rc', c.summary || c.root_cause_service || 'No root cause supported by the evidence'));
    card.append(el('div', 'sre-basis', band.basis + ' (model: ' + (c.confidence ?? '–') + ')'));
    const grid = el('div', 'sre-concl-grid');
    const impact = el('div', 'sre-concl-box'); impact.append(el('div', 'sre-concl-label', 'Impact'), el('p', null, c.impact || 'Not measured.'));
    const act = el('div', 'sre-concl-box action');
    act.append(el('div', 'sre-concl-label', 'Recommended action'), el('div', 'sre-action-type', niceAction(c.proposed_action)), el('p', 'sre-small', short(c.rationale, 260)),
      (() => { const g = el('div', 'sre-gate'); g.append(icon('shield'), document.createTextNode(/awaiting/.test(st) ? 'Waiting for a human to approve in the agent console' : 'Proposed only')); return g; })());
    grid.append(impact, act);
    card.append(grid);
    const tools = events.filter(e => e.event === 'sre.rca.tool').length;
    const subs = nodes.filter(n => n.start).length;
    const meta = el('div', 'sre-meta');
    [['clock', 'Duration', Math.round(c.seconds || 0) + ' s'], ['users', 'Sub-agents', isTree(c) ? subs : '–'], ['tool', 'Tool calls', tools || '–'], ['chip', 'Model calls', c.requests || '–'],
     ['tokens', 'Tokens in / out', num(c.input_tokens) + ' / ' + num(c.output_tokens)], ['coin', 'Model cost', money(c.cost_usd)], ['chip', 'Models', short(c.model, 60)]]
      .forEach(([ic, k, v]) => { const d = el('div', 'sre-meta-i'); const kk = el('span', 'sre-meta-k'); kk.append(icon(ic), document.createTextNode(k)); d.append(kk, el('span', 'sre-meta-v', v)); meta.append(d); });
    card.append(meta);
    card.append(el('div', 'sre-small', `${c.case_id} · ${fmtTime(c.t)} · trigger: ${(c.detectors || []).map(cleanDet).join(' · ')} · started by ${S.sources[c.case_id] || 'agent'}`));
    return card;
  }

  // ---------- detail: hypothesis tree (vertical split: tree | selected hypothesis) ----------
  function treeView(nodes, c, tools) {
    const wrap = el('div', 'sre-tree');
    const bar = el('div', 'sre-treebar');
    const counts = {}; nodes.forEach(n => { counts[n.status] = (counts[n.status] || 0) + 1; });
    ['validated', 'invalidated', 'inconclusive', 'not tested'].forEach(k => { if (counts[k]) { const s = STATUS[k]; bar.append(ichip(s.icon, `${s.label} ${counts[k]}`, s.cls)); } });
    const tog = el('label', 'sre-toggle'); const cb = el('input'); cb.type = 'checkbox'; cb.id = 'sre-ruled'; cb.checked = S.showRuledOut;
    tog.append(cb, document.createTextNode(' Show ruled-out branches'));
    bar.append(tog);
    wrap.append(bar);

    const split = el('div', 'sre-split');
    const left = el('div', 'sre-split-tree'); left.setAttribute('role', 'tree'); left.setAttribute('aria-label', 'Hypothesis tree');
    const right = el('div', 'sre-split-detail'); right.setAttribute('aria-live', 'polite');
    split.append(left, right);
    wrap.append(split);

    const kids = {}; nodes.forEach(n => { (kids[n.parent || ''] = kids[n.parent || ''] || []).push(n); });
    const leafId = pickRootCause(nodes, c);
    let selected = leafId || (nodes.find(n => n.status === 'validated') || nodes[0] || {}).id;
    const rows = {};

    const alertRow = el('div', 'sre-trow is-alert');
    const ai = el('span', 'sre-icon is-alert'); ai.append(icon('bang', null, 13));
    alertRow.append(ai, el('span', 'sre-trow-text', (c.detectors || []).map(cleanDet).join(' · ') || 'Alert'));
    left.append(alertRow);

    function addRows(pid, depth, guides) {
      const items = kids[pid] || [];
      items.forEach((n, i) => {
        const last = i === items.length - 1;
        const s = STATUS[n.status] || STATUS.inconclusive;
        const row = el('button', 'sre-trow ' + s.cls + (n.id === leafId ? ' leaf' : '') + (n.status === 'invalidated' ? ' ruled' : ''));
        row.type = 'button'; row.setAttribute('role', 'treeitem'); row.dataset.id = n.id;
        const g = el('span', 'sre-guides');
        guides.forEach(on => g.append(el('span', 'sre-guide' + (on ? ' on' : ''))));
        g.append(el('span', 'sre-guide elbow' + (last ? ' last' : '')));
        const ic = el('span', 'sre-icon ' + s.cls); ic.append(icon(s.icon, null, 12));
        const txt = el('span', 'sre-trow-text');
        txt.append(el('span', 'sre-hyp-id', n.id + ' '), document.createTextNode(n.statement || ''));
        row.append(g, ic, txt);
        if (n.id === leafId) { const m = el('span', 'sre-trow-flag'); m.append(icon('target', null, 12)); m.title = 'Root cause'; row.append(m); }
        row.addEventListener('click', () => select(n.id));
        rows[n.id] = row;
        left.append(row);
        addRows(n.id, depth + 1, guides.concat([!last]));
      });
    }
    addRows('', 0, []);

    function applyFilter() {
      wrap.classList.toggle('hide-ruled', !cb.checked);
      S.showRuledOut = cb.checked;
    }
    cb.addEventListener('change', applyFilter); applyFilter();

    function select(id) {
      selected = id;
      Object.entries(rows).forEach(([k, r]) => { r.classList.toggle('sel', k === id); r.setAttribute('aria-selected', k === id ? 'true' : 'false'); });
      const n = nodes.find(x => x.id === id);
      right.textContent = '';
      if (!n) { right.append(el('div', 'sre-empty', 'Select a hypothesis.')); return; }
      right.append(nodeDetail(n, n.id === leafId, tools));
    }
    select(selected);
    return wrap;
  }

  function nodeDetail(n, isLeaf, tools) {
    const s = STATUS[n.status] || STATUS.inconclusive;
    const box = el('div', 'sre-nd');
    const head = el('div', 'sre-nd-head');
    const ic = el('span', 'sre-icon big ' + s.cls); ic.append(icon(s.icon, null, 16));
    const ht = el('div', 'sre-nd-title');
    ht.append(el('div', 'sre-hyp-id', n.id + (n.depth ? ' · level ' + n.depth : '')), el('div', 'sre-nd-statement', n.statement || ''));
    head.append(ic, ht);
    box.append(head);
    const chips = el('div', 'sre-node-chips');
    chips.append(ichip(s.icon, s.label, s.cls));
    if (isLeaf) chips.append(ichip('target', 'Root cause', 'is-accent'));
    if (n.component && n.component !== 'none') chips.append(ichip('chip', short(n.component, 50), 'is-muted'));
    box.append(chips);
    if (n.flat) { box.append(el('div', 'sre-small', 'Single-loop investigation: hypotheses were tested by one agent, without sub-agents or code checks per branch.')); return box; }

    // 1. Result first: what the sub-agent said, what code decided, why
    const res = el('section', 'sre-nd-sec');
    res.append(el('div', 'sre-blk-k', 'Result'));
    const two = el('div', 'sre-two');
    const ms = STATUS[n.model_verdict] || STATUS.inconclusive;
    const said = el('div', 'sre-said'); said.append(el('div', 'sre-small', 'Sub-agent said'), ichip(ms.icon, ms.label, ms.cls));
    const code = el('div', 'sre-said'); code.append(el('div', 'sre-small', 'Code decided'), ichip(s.icon, s.label, s.cls));
    two.append(said, code); res.append(two);
    const note = (n.checks || []).slice(-1)[0];
    if (note) res.append(el('div', 'sre-check ' + (n.status === 'validated' ? 'is-ok' : 'is-warn'), note));
    box.append(res);

    // 2. Evidence
    const ev = el('section', 'sre-nd-sec');
    ev.append(el('div', 'sre-blk-k', 'Evidence'));
    if (n.finding) ev.append(el('p', null, n.finding));
    (n.evidence || []).forEach(e => { const r = el('div', 'sre-ev'); r.append(chip(e.signal || '?', 'is-muted'), document.createTextNode(' ' + (e.finding || '') + ' '), evidenceLink(e.evidence_id, tools)); ev.append(r); });
    if (!n.finding && !(n.evidence || []).length) ev.append(el('div', 'sre-small', 'No evidence recorded for this branch (events from before 27 Oct 07:40Z carry only the verdict).'));
    if (n.last_seen_utc) ev.append(el('div', 'sre-small', 'Signal last seen: ' + n.last_seen_utc));
    box.append(ev);

    // 3. What was checked
    const ck = el('section', 'sre-nd-sec');
    ck.append(el('div', 'sre-blk-k', 'Checked'));
    if (n.test_plan) ck.append(el('div', 'sre-small', 'Planned test: ' + n.test_plan));
    const steps = n.tools || [];
    if (steps.length) {
      const ol = el('ol', 'sre-steps');
      steps.forEach(tu => { const li = el('li'); li.append(el('span', 'sre-step-tool', tu.tool), document.createTextNode(' ' + short((tu.args || {}).why || '', 220))); ol.append(li); });
      ck.append(ol);
    }
    ck.append(el('div', 'sre-small', `${n.tool_calls || steps.length || 0} tool calls · ${Math.round(n.seconds || 0)} s`));
    box.append(ck);
    if ((n.children_proposed || []).length && n.status !== 'validated') {
      box.append(el('div', 'sre-small', 'Deeper hypotheses were proposed but not opened, because code did not validate this branch.'));
    }
    return box;
  }

  // ---------- detail: timeline ----------
  function timelineView(nodes, events) {
    const workers = nodes.filter(n => n.start && n.end);
    if (!workers.length) return el('div', 'sre-empty', 'No sub-agents in this investigation (single agent loop).');
    const startEv = events.find(e => e.event === 'sre.case.investigating') || events[0];
    const t0 = Math.min(startEv ? startEv.t : Infinity, ...workers.map(n => n.start));
    const firstBranch = events.find(e => e.event === 'sre.tree.branch');
    const done = S.cases.find(c => c.case_id === S.selected);
    const tEnd = done ? done.t : 0;
    const t1 = Math.max(tEnd, ...workers.map(n => n.end));
    const span = Math.max(1, t1 - t0);
    const rows = [{ label: 'Collect + plan', s: t0, e: firstBranch ? firstBranch.t : t0, cls: 'is-plan' }]
      .concat(workers.map(n => ({ label: n.id, s: n.start, e: n.end, cls: (STATUS[n.status] || STATUS.inconclusive).cls, title: n.id + ' ' + n.statement })));
    const lastVerdict = Math.max(...workers.map(n => n.end));
    if (tEnd > lastVerdict) rows.push({ label: 'Decide', s: lastVerdict, e: tEnd, cls: 'is-plan' });
    const W = 900, L = 120, R = 50, rowH = 28, top = 18;
    const H = top + rows.length * rowH + 30;
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'sre-gantt');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Investigation timeline: one bar per sub-agent, coloured by the code decision');
    const x = v => L + (v - t0) / span * (W - L - R);
    function add(tag, attrs, text) { const n = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v)); if (text !== undefined) n.textContent = text; svg.append(n); return n; }
    const step = span > 240 ? 60 : span > 90 ? 30 : 10;
    for (let s = 0; s <= span; s += step) { add('line', { x1: x(t0 + s), x2: x(t0 + s), y1: top - 4, y2: H - 22, class: 'grid' }); add('text', { x: x(t0 + s), y: H - 6, class: 'axis', 'text-anchor': 'middle' }, s + ' s'); }
    rows.forEach((r, i) => {
      const y = top + i * rowH;
      add('text', { x: L - 10, y: y + 16, class: 'lbl', 'text-anchor': 'end' }, r.label);
      const bar = add('rect', { x: x(r.s), y: y + 5, width: Math.max(3, x(r.e) - x(r.s)), height: rowH - 12, rx: 4, class: 'bar ' + r.cls });
      if (r.title) { const tt = document.createElementNS(NS, 'title'); tt.textContent = r.title; bar.append(tt); }
      add('text', { x: Math.min(W - R + 40, x(r.e) + 6), y: y + 16, class: 'dur' }, Math.round(r.e - r.s) + ' s');
    });
    const box = el('div', 'sre-gantt-wrap'); box.append(svg);
    const overlap = workers.length > 1 && workers.some((a, i) => workers.some((b, j) => i !== j && a.start < b.end && b.start < a.end));
    box.append(el('div', 'sre-small', overlap ? 'Overlapping bars ran at the same time: one sub-agent per hypothesis, in parallel. Colour = the code decision.' : 'The sub-agents ran one after another in this investigation.'));
    return box;
  }

  // ---------- detail: evidence + trace ----------
  function evidenceView(c, tools) {
    if (!(c.evidence || []).length) return el('div', 'sre-empty', 'No evidence recorded.');
    const t = el('table', 'sre-table'); const tr = el('tr'); ['Signal', 'Finding', 'Source'].forEach(h => tr.append(el('th', null, h))); t.append(tr);
    c.evidence.forEach(ev => { const r = el('tr'); const s = el('td'); s.append(evidenceLink(ev.evidence_id, tools)); r.append(el('td', null, ev.signal), el('td', null, ev.finding), s); t.append(r); });
    const w = el('div', 'sre-scroll'); w.append(t);
    const box = el('div'); box.append(w);
    if ((c.cause_chain || []).length) { box.append(el('h3', null, 'Cause chain (root cause → alert)')); const ol = el('ol', 'sre-chain'); c.cause_chain.forEach(x => ol.append(el('li', null, x))); box.append(ol); }
    if ((c.ruled_out || []).length) { box.append(el('h3', null, 'Ruled out')); const ul = el('ul'); c.ruled_out.forEach(x => ul.append(el('li', null, x))); box.append(ul); }
    return box;
  }
  function traceView(events, t0) {
    const steps = events.filter(e => e.event === 'sre.rca.tool');
    if (!steps.length) return el('div', 'sre-empty', 'No tool calls recorded.');
    const ol = el('ol', 'sre-trace');
    steps.forEach(e => {
      const li = el('li', e.ok === false ? 'is-err' : '');
      const head = el('div', 'sre-trace-head');
      head.append(el('span', 'sre-trace-t', '+' + Math.round((e.t || t0) - t0) + ' s'), chip(e.node || 'agent', 'is-muted'), el('span', 'sre-step-tool', e.tool), chip(e.ok === false ? 'error' : (e.summary || 'is-ok'), e.ok === false ? 'is-bad' : 'is-muted'));
      li.append(head);
      if (e.args && e.args.why) li.append(el('div', 'sre-trace-why', e.args.why));
      if (e.preview) { const d = el('details', 'sre-more'); d.append(el('summary', null, 'Result preview'), el('pre', null, String(e.preview).slice(0, 1500))); li.append(d); }
      ol.append(li);
    });
    return ol;
  }

  // ---------- detail ----------
  async function showDetail(c) {
    detail.textContent = '';
    const loading = el('div', 'sre-empty', 'Loading investigation…'); detail.append(loading);
    let events = [];
    try { events = await loadDetail(c.case_id); } catch (e) { loading.textContent = 'Could not load the investigation: ' + e.message; return; }
    if (S.selected !== c.case_id) return;
    detail.textContent = '';
    const nodes = buildTree(events, c);
    const tools = toolIndex(events);
    detail.append(conclusion(c, nodes, events));
    const tabs = el('div', 'sre-tabs'); tabs.setAttribute('role', 'tablist');
    const pane = el('div', 'sre-pane');
    const t0 = (events.find(e => e.event === 'sre.case.investigating') || events[0] || { t: c.t }).t;
    const TABS = [['tree', isTree(c) ? 'Hypothesis tree' : 'Hypotheses', 'branch'], ['timeline', 'Timeline', 'gantt'], ['evidence', 'Evidence', 'evidence'], ['trace', 'Agent trace', 'terminal'], ['narrative', 'Narrative', 'book']];
    function show(k) {
      S.tab = k; pane.textContent = '';
      [...tabs.children].forEach(b => b.setAttribute('aria-selected', b.dataset.k === k ? 'true' : 'false'));
      if (k === 'tree') pane.append(nodes.length ? treeView(nodes, c, tools) : el('div', 'sre-empty', 'No hypotheses recorded.'));
      if (k === 'timeline') pane.append(timelineView(nodes, events));
      if (k === 'evidence') pane.append(evidenceView(c, tools));
      if (k === 'trace') pane.append(traceView(events, t0));
      if (k === 'narrative') pane.append(el('p', 'sre-narr', c.narrative || 'No narrative.'));
    }
    TABS.forEach(([k, label, ic]) => { const b = el('button', 'sre-tab'); b.append(icon(ic, null, 15), document.createTextNode(label)); b.type = 'button'; b.dataset.k = k; b.setAttribute('role', 'tab'); b.addEventListener('click', () => show(k)); tabs.append(b); });
    detail.append(tabs, pane);
    show(S.tab);
  }

  async function refresh(force) {
    stamp.textContent = 'Loading…';
    try {
      await loadCases();
      renderFleet();
      const first = !S.selected;
      if (first && S.cases.length) S.selected = S.cases[0].case_id;
      renderList();
      const c = S.cases.find(x => x.case_id === S.selected);
      if (c && (first || force)) showDetail(c);
      stamp.textContent = 'Updated ' + fmtClock(Date.now() / 1000);
    } catch (e) { stamp.textContent = 'Error: ' + e.message; }
  }
  refresh(true);
  setInterval(() => refresh(false), 30000);
})();
