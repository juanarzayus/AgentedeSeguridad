/* SecScan Web — cliente.
 * Regla de seguridad: el contenido dinámico (rutas, nombres, hallazgos) se inserta
 * SIEMPRE con textContent; nunca con innerHTML. Los íconos vienen de <template>. */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const readJSON = id => JSON.parse(document.getElementById(id).textContent);
  const STRINGS = readJSON('i18n-data');
  const SKILLS = readJSON('skills-data');
  const PATHS = readJSON('paths-data');
  const CSRF = document.querySelector('meta[name="csrf-token"]').content;
  const SEVERITIES = ['CRITICA', 'ALTA', 'MEDIA', 'BAJA'];
  const SEV_ICON = { CRITICA: 'icon-crit', ALTA: 'icon-high', MEDIA: 'icon-med', BAJA: 'icon-low' };
  const LEVEL_ICON = { critical: 'icon-crit', serious: 'icon-high', warning: 'icon-med', good: 'icon-shield' };
  const LEVEL_COLOR = { critical: '--critical', serious: '--serious', warning: '--warning', good: '--good' };
  const PHASES = ['observe', 'reason', 'act', 'report'];
  const POLL_MS = 350;

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* sin almacenamiento */ } },
  };

  let lang = store.get('secscan-lang') || (navigator.language || 'es').slice(0, 2);
  if (!STRINGS[lang]) lang = 'es';

  const t = (key, vars = {}) => {
    let s = (STRINGS[lang] && STRINGS[lang][key]) ?? STRINGS.es[key] ?? key;
    for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
    return s;
  };

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'style') node.style.cssText = v; // CSSOM: permitido por la CSP (el atributo no)
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c);
    return node;
  };
  const iconNode = id => document.getElementById(id).content.firstElementChild.cloneNode(true);

  // ═══════════ Idioma y tema ═══════════

  function applyLang() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(n => { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll('[data-i18n-title]').forEach(n => {
      n.title = t(n.dataset.i18nTitle); n.setAttribute('aria-label', n.title);
    });
    document.querySelectorAll('.lang-btn').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
    renderSkills();
    if (current.scan) rerender();
    loadHistory();
  }

  document.querySelectorAll('.lang-btn').forEach(b => b.addEventListener('click', () => {
    lang = b.dataset.lang; store.set('secscan-lang', lang); applyLang();
  }));

  const savedTheme = store.get('secscan-theme');
  if (savedTheme) document.documentElement.dataset.theme = savedTheme;
  $('#theme-toggle').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    store.set('secscan-theme', next);
  });

  // ═══════════ Formulario ═══════════

  function renderSkills() {
    const box = $('#skills');
    const selected = box.querySelector('input:checked')?.value || 'full_security_review';
    box.replaceChildren(...SKILLS.map(s => {
      const input = el('input', { type: 'radio', name: 'skill', value: s.key });
      input.checked = s.key === selected;
      return el('label', { class: 'skill' }, input,
        el('strong', { text: t(`skill_${s.key}`) === `skill_${s.key}` ? s.name : t(`skill_${s.key}`) }),
        el('span', { text: t(`skill_${s.key}_desc`) === `skill_${s.key}_desc` ? s.description : t(`skill_${s.key}_desc`) }));
    }));
  }

  const formError = $('#form-error');
  const showError = (node, key) => { node.textContent = t(`err_${key}`) === `err_${key}` ? t('err_generic') : t(`err_${key}`); node.hidden = false; };

  async function api(path, options = {}) {
    const res = await fetch(path, {
      credentials: 'same-origin',
      ...options,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF, ...(options.headers || {}) },
    });
    if (res.status === 401) throw Object.assign(new Error('session'), { code: 'session' });
    let data = null;
    try { data = await res.json(); } catch { /* respuesta vacía */ }
    if (!res.ok) throw Object.assign(new Error('api'), { code: data?.error || 'generic' });
    return data;
  }

  $('#scan-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    formError.hidden = true;
    const payload = {
      target: $('#target').value.trim(),
      logs: $('#logs').value.trim() || null,
      skill: $('#skills input:checked')?.value,
      lang,
    };
    if (!payload.target) return showError(formError, 'missing');
    setRunning(true);
    try {
      const { id } = await api('/api/scans', { method: 'POST', body: JSON.stringify(payload) });
      store.set('secscan-last-target', payload.target);
      if (payload.logs) store.set('secscan-last-logs', payload.logs);
      follow(id);
    } catch (e) {
      setRunning(false);
      showError(formError, e.code);
    }
  });

  function setRunning(on) {
    const btn = $('#run-btn');
    btn.disabled = on;
    btn.querySelector('[data-i18n]').dataset.i18n = on ? 'running' : 'run';
    btn.querySelector('[data-i18n]').textContent = t(on ? 'running' : 'run');
  }

  // ═══════════ Selector de carpetas (solo lista subcarpetas) ═══════════

  const picker = $('#picker');
  let pickerTarget = null, pickerPath = null, pickerParent = null;

  async function openDir(path) {
    try {
      const data = await api(`/api/fs?path=${encodeURIComponent(path || '')}`);
      pickerPath = data.path; pickerParent = data.parent;
      $('#picker-path').textContent = data.path;
      $('#picker-up').disabled = !data.parent;
      const list = $('#picker-list');
      if (!data.dirs.length) list.replaceChildren(el('li', { class: 'muted small', text: t('empty_dir'), style: 'padding:10px' }));
      else list.replaceChildren(...data.dirs.map(name => {
        const b = el('button', { type: 'button' }, iconNode('icon-folder'), el('span', { text: name }));
        b.addEventListener('click', () => openDir(`${data.path.replace(/\/$/, '')}/${name}`));
        return el('li', {}, b);
      }));
    } catch { if (path) openDir(''); }
  }

  document.querySelectorAll('[data-browse]').forEach(b => b.addEventListener('click', () => {
    pickerTarget = $(`#${b.dataset.browse}`);
    picker.showModal();
    openDir(pickerTarget.value.trim() || PATHS.cwd);
  }));
  $('#picker-cancel').addEventListener('click', () => picker.close());
  $('#picker-up').addEventListener('click', () => pickerParent && openDir(pickerParent));
  $('#picker-use').addEventListener('click', () => { if (pickerTarget && pickerPath) pickerTarget.value = pickerPath; picker.close(); });

  // ═══════════ Seguimiento en vivo ═══════════

  const current = { id: null, scan: null, events: [], next: 0, timer: null };

  function follow(id) {
    clearTimeout(current.timer);
    Object.assign(current, { id, scan: null, events: [], next: 0 });
    $('#idle').hidden = true; $('#live').hidden = false;
    resetLive();
    poll();
  }

  async function poll() {
    const id = current.id;
    try {
      const data = await api(`/api/scans/${encodeURIComponent(id)}?since=${current.next}`);
      if (id !== current.id) return;
      current.scan = data;
      current.events.push(...data.events);
      current.next = data.next;
      data.events.forEach(applyEvent);
      updateHeader();
      if (data.status === 'done' || data.status === 'error') {
        setRunning(false);
        loadHistory();
        return;
      }
    } catch (e) {
      if (e.code === 'session') { setRunning(false); return showError(formError, 'session'); }
      if (e.code === 'request_rejected') { setRunning(false); return; } // análisis ya no existe
    }
    current.timer = setTimeout(poll, POLL_MS);
  }

  function resetLive() {
    ['#card-observe', '#card-plan', '#card-act', '#result'].forEach(s => { $(s).hidden = true; });
    $('#facts').replaceChildren(); $('#plan').replaceChildren(); $('#tools').replaceChildren();
    document.querySelectorAll('#stepper li').forEach(li => li.classList.remove('active', 'done'));
    $('#download-error').hidden = true;
  }

  function rerender() {
    resetLive();
    current.events.forEach(applyEvent);
    updateHeader();
  }

  function updateHeader() {
    const s = current.scan;
    if (!s) return;
    $('#live-target').textContent = s.target;
    $('#live-skill').textContent = t(`skill_${s.skill}`);
    const status = { queued: t('running'), running: t('running'), done: '', error: t('err_generic') }[s.status];
    $('#live-status').textContent = status;
  }

  function setPhase(key) {
    const idx = PHASES.indexOf(key);
    document.querySelectorAll('#stepper li').forEach((li, i) => {
      li.classList.toggle('done', i < idx);
      li.classList.toggle('active', i === idx);
    });
  }

  const reveal = node => { if (node.hidden) { node.hidden = false; node.classList.add('appear'); } };

  function applyEvent(ev) {
    switch (ev.type) {
      case 'phase': setPhase(ev.key); break;
      case 'context': renderContext(ev); break;
      case 'plan': renderPlan(ev); break;
      case 'step_start': renderStepStart(ev); break;
      case 'step_end': renderStepEnd(ev); break;
      case 'done':
        document.querySelectorAll('#stepper li').forEach(li => { li.classList.remove('active'); li.classList.add('done'); });
        renderResult(ev.summary); break;
      case 'error':
        document.querySelectorAll('#stepper li.active').forEach(li => li.classList.remove('active'));
        showError(formError, 'generic'); break;
    }
  }

  function renderContext(c) {
    const langs = [c.python && 'Python', c.js && 'JavaScript', c.html && 'HTML'].filter(Boolean).join(', ') || '—';
    const yn = v => el('dd', { class: v ? 'yes' : '', text: t(v ? 'yes' : 'no') });
    const rows = [
      [t('files'), el('dd', { text: String(c.total_files) })],
      [t('languages'), el('dd', { text: langs })],
      [t('dependencies'), yn(c.dependencies)],
      [t('configuration'), yn(c.config)],
      [t('logs_short'), yn(c.logs)],
    ];
    if (c.ignored) rows.push([t('ignored'), el('dd', { text: String(c.ignored) })]);
    $('#facts').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k }), v]));
    reveal($('#card-observe'));
  }

  function renderPlan(p) {
    $('#plan').replaceChildren(...p.steps.map(s => el('li', {},
      el('span', { class: 'n', text: String(s.order) }),
      el('div', {}, el('div', { class: 'tool', text: s.tool }),
        el('div', { class: 'reason', text: s.reason.split('. ')[0].replace(/\.$/, '') })))));
    let note = t('plan_note', { n: p.steps.length, total: p.available });
    if (p.skipped.length) note += ` · ${t('skipped')}: ${p.skipped.join(', ')}`;
    $('#plan-note').textContent = note;
    reveal($('#card-plan'));
    $('#tools').replaceChildren(...p.steps.map(s => el('li', { 'data-tool': s.tool, class: 'waiting' },
      el('span', { class: 'state' }), el('span', { class: 't-name', text: s.tool }), el('span', { class: 't-detail' }))));
  }

  const toolRow = name => $(`#tools li[data-tool="${CSS.escape(name)}"]`);

  function renderStepStart(s) {
    reveal($('#card-act'));
    const row = toolRow(s.tool);
    if (row) row.className = 'pending';
  }

  function renderStepEnd(s) {
    const row = toolRow(s.tool);
    if (!row) return;
    const ok = s.status !== 'error';
    row.className = ok ? 'ok' : 'fail';
    row.querySelector('.state').replaceChildren(iconNode(ok ? 'icon-check' : 'icon-x'));
    const detail = ok ? (s.findings ? t('findings_n', { n: s.findings }) : t('no_findings')) : t('failed');
    row.querySelector('.t-detail').textContent = `${detail} · ${(s.seconds >= 0.01 ? t('seconds', { n: s.seconds.toFixed(2) }) : '< 0.01 s')}`;
  }

  // ═══════════ Resultado ═══════════

  function gauge(score, level) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = $('#gauge');
    const arc = (attrs) => { const p = document.createElementNS(svgNS, 'path'); for (const [k, v] of Object.entries(attrs)) p.setAttribute(k, v); return p; };
    const r = 80, cx = 100, cy = 100, len = Math.PI * r;
    const d = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
    const track = arc({ d, class: 'track', fill: 'none', 'stroke-width': 14, 'stroke-linecap': 'round' });
    const value = arc({ d, fill: 'none', 'stroke-width': 14, 'stroke-linecap': 'round',
      'stroke-dasharray': `${len} ${len}`, 'stroke-dashoffset': String(len) });
    value.style.stroke = `var(${LEVEL_COLOR[level]})`;
    svg.replaceChildren(track, value);
    const target = len * (1 - Math.max(score, 0.5) / 100);
    requestAnimationFrame(() => {
      value.style.transition = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'none' : 'stroke-dashoffset .9s ease-out';
      value.setAttribute('stroke-dashoffset', String(target));
    });
  }

  function badge(sev) {
    return el('span', { class: `badge sev-${sev}` }, iconNode(SEV_ICON[sev]), el('span', { text: t(`sev_${sev}`) }));
  }

  function renderResult(sum) {
    if (!sum) return;
    const id = current.id;
    $('#score').textContent = String(sum.risk_score);
    gauge(sum.risk_score, sum.verdict);
    $('#verdict').className = `verdict lvl-${sum.verdict}`;
    $('#verdict-icon').replaceChildren(iconNode(LEVEL_ICON[sum.verdict]));
    $('#verdict-text').textContent = t(`verdict_${sum.verdict}`);

    $('#tiles').replaceChildren(...SEVERITIES.map(sev => el('div', { class: `tile sev-${sev}` },
      el('div', { class: 'tile-label' }, iconNode(SEV_ICON[sev]), el('span', { text: t(`sev_${sev}`) })),
      el('div', { class: 'tile-value', text: String(sum.severity_counts[sev] || 0) }))));
    const total = SEVERITIES.reduce((a, s) => a + (sum.severity_counts[s] || 0), 0);
    $('#stack').replaceChildren(...SEVERITIES.filter(s => sum.severity_counts[s]).map(s =>
      el('div', { class: `seg-bar sev-${s}`, style: `flex:${sum.severity_counts[s]}`, title: `${t(`sev_${s}`)}: ${sum.severity_counts[s]}` })));
    $('#stack').hidden = total === 0;
    $('#threats-line').textContent = sum.threat_events ? `${t('threats')}: ${sum.threat_events}` : '';
    $('#tool-errors').hidden = !sum.tool_errors;
    $('#tool-errors').textContent = sum.tool_errors ? t('tool_errors', { n: sum.tool_errors }) : '';

    const base = `/scans/${encodeURIComponent(id)}`;
    $('#open-report').href = `${base}/report`;
    $('#dl-html').href = `${base}/download/html`;
    $('#dl-json').href = `${base}/download/json`;
    $('#dl-pdf').href = `${base}/download/pdf`;

    $('#actions').replaceChildren(...sum.actions.slice(0, 5).map((a, i) => el('li', {},
      el('span', { class: 'n', text: String(i + 1) }),
      el('div', {}, el('div', { class: 'a-title', text: t(`action_${a.key}`) }),
        el('div', { class: 'a-meta', text: `${t('findings_n', { n: a.count })} · ${t(`effort_${a.effort}`)}` })),
      badge(a.max_severity))));
    $('#top').replaceChildren(...sum.top.map(f => el('li', {}, badge(f.severity),
      el('span', { text: f.type }), el('span', { class: 'loc', text: f.cwe ? `${f.location} · ${f.cwe}` : f.location }))));
    reveal($('#result'));
  }

  // El PDF puede tardar unos segundos o no estar disponible: se valida antes de descargar
  $('#dl-pdf').addEventListener('click', async ev => {
    ev.preventDefault();
    const link = ev.currentTarget, err = $('#download-error');
    err.hidden = true;
    link.setAttribute('aria-disabled', 'true');
    try {
      const res = await fetch(link.href, { credentials: 'same-origin' });
      if (!res.ok) {
        let code = 'generic';
        try { code = (await res.json()).error || code; } catch { /* sin JSON */ }
        throw Object.assign(new Error(), { code });
      }
      const url = URL.createObjectURL(await res.blob());
      const a = el('a', { href: url, download: `secscan-${current.id.slice(0, 8)}.pdf` });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e) { showError(err, e.code || 'generic'); }
    finally { link.removeAttribute('aria-disabled'); }
  });

  // ═══════════ Historial ═══════════

  async function loadHistory() {
    let data;
    try { data = await api('/api/scans'); } catch { return; }
    const list = $('#history-list');
    $('#history-empty').hidden = data.scans.length > 0;
    list.replaceChildren(...data.scans.map(s => {
      const date = new Date(s.created_at * 1000).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit' });
      const meta = s.status === 'done' ? `${t(`skill_${s.skill}`)} · ${date}` : `${t(s.status === 'error' ? 'err_generic' : 'running')} · ${date}`;
      const b = el('button', { type: 'button' },
        el('span', { class: 'h-target', text: s.target, title: s.target }),
        el('span', { class: `h-score ${s.verdict ? `lvl-${s.verdict}` : ''}`, text: s.risk_score ?? '' }),
        el('span', { class: 'h-meta', text: meta }));
      b.addEventListener('click', () => follow(s.id));
      return el('li', {}, b);
    }));
    if (data.busy && !current.id && data.scans[0]) { setRunning(true); follow(data.scans[0].id); }
  }

  // ═══════════ Inicio ═══════════
  $('#target').value = store.get('secscan-last-target') || '';
  $('#logs').value = store.get('secscan-last-logs') || '';
  applyLang();
})();
