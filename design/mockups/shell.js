/*
 * Tenko DDI mockup shell behavior. Plain JavaScript, no dependencies.
 * Loaded by every mockup with <script src="shell.js" defer></script>.
 *
 * Provides: icon sprite (<svg class="i"><use href="#i-name"/></svg>),
 * theme toggle (system -> light -> dark, persisted as "tenko-theme"),
 * density switch, command palette (Ctrl+K), keyboard sheet (?),
 * "g" navigation chords, toasts (window.tenko.toast), mockup notes drawer.
 */
(function () {
  'use strict';

  /* ---------------- Icon sprite ---------------- */
  var ICONS = {
    ipam: '<rect x="2.25" y="2.25" width="4.75" height="4.75" rx="1"/><rect x="9" y="2.25" width="4.75" height="4.75" rx="1"/><rect x="2.25" y="9" width="4.75" height="4.75" rx="1"/><rect x="9" y="9" width="4.75" height="4.75" rx="1" stroke-dasharray="2 1.6"/>',
    dns: '<circle cx="8" cy="8" r="6.25"/><path d="M1.75 8h12.5M8 1.75c1.8 1.9 2.6 4 2.6 6.25s-.8 4.35-2.6 6.25M8 1.75C6.2 3.65 5.4 5.75 5.4 8s.8 4.35 2.6 6.25"/>',
    dhcp: '<path d="M2.25 4.25h7.5L13.75 8l-4 3.75h-7.5z"/><circle cx="5.25" cy="8" r="1"/>',
    topology: '<circle cx="8" cy="3.25" r="1.75"/><circle cx="3.25" cy="12.75" r="1.75"/><circle cx="12.75" cy="12.75" r="1.75"/><path d="M8 5v3M8 8 4.4 11.4M8 8l3.6 3.4"/>',
    jobs: '<path d="M7 4.25h6.75M7 8h6.75M7 11.75h4.5M2.25 4.25l1 1 1.75-2M2.25 8l1 1 1.75-2"/><circle cx="3.5" cy="11.75" r="1.1"/>',
    settings: '<path d="M2.25 4.5h4.25M9.75 4.5h4M2.25 11.5h7.5M12.75 11.5h1"/><circle cx="8.1" cy="4.5" r="1.6"/><circle cx="11.25" cy="11.5" r="1.6"/>',
    dashboard: '<path d="M2.25 11.5a5.75 5.75 0 1 1 11.5 0"/><path d="M8 11.5 10.75 7.75"/><path d="M2.25 13.75h11.5"/>',
    search: '<circle cx="7" cy="7" r="4.5"/><path d="m10.4 10.4 3.35 3.35"/>',
    sun: '<circle cx="8" cy="8" r="2.75"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.05 1.05M11.55 11.55l1.05 1.05M3.4 12.6l1.05-1.05M11.55 4.45l1.05-1.05"/>',
    moon: '<path d="M13.25 9.6A5.5 5.5 0 1 1 6.4 2.75a4.4 4.4 0 0 0 6.85 6.85Z"/>',
    system: '<circle cx="8" cy="8" r="5.75"/><path d="M8 2.25v11.5A5.75 5.75 0 0 1 8 2.25Z" fill="currentColor"/>',
    'chev-r': '<path d="M6 3.5 10.5 8 6 12.5"/>',
    'chev-d': '<path d="M3.5 6 8 10.5 12.5 6"/>',
    'chev-u': '<path d="M3.5 10 8 5.5 12.5 10"/>',
    lock: '<rect x="3.25" y="7.25" width="9.5" height="6.5" rx="1"/><path d="M5.5 7.25V5.5a2.5 2.5 0 0 1 5 0v1.75"/>',
    unlock: '<rect x="3.25" y="7.25" width="9.5" height="6.5" rx="1"/><path d="M5.5 7.25V5.5a2.5 2.5 0 0 1 4.85-.85"/>',
    alert: '<path d="M8 2.25 14.25 13H1.75L8 2.25Z"/><path d="M8 6.5v3M8 11.25v.01"/>',
    conflict: '<path d="M5.4 1.75h5.2l3.65 3.65v5.2l-3.65 3.65H5.4L1.75 10.6V5.4L5.4 1.75Z"/><path d="M8 5v3.5M8 10.75v.01"/>',
    check: '<path d="m3 8.5 3 3 7-7"/>',
    x: '<path d="m4 4 8 8M12 4l-8 8"/>',
    undo: '<path d="M5.5 4 2.5 7l3 3"/><path d="M2.5 7h7.25a3.25 3.25 0 0 1 0 6.5H8"/>',
    drag: '<circle cx="6" cy="4" r=".9" fill="currentColor" stroke="none"/><circle cx="10" cy="4" r=".9" fill="currentColor" stroke="none"/><circle cx="6" cy="8" r=".9" fill="currentColor" stroke="none"/><circle cx="10" cy="8" r=".9" fill="currentColor" stroke="none"/><circle cx="6" cy="12" r=".9" fill="currentColor" stroke="none"/><circle cx="10" cy="12" r=".9" fill="currentColor" stroke="none"/>',
    filter: '<path d="M2.25 3h11.5L9.25 8.5V13l-2.5-1.25V8.5L2.25 3Z"/>',
    plus: '<path d="M8 3v10M3 8h10"/>',
    export: '<path d="M8 2.5v7M5 5.5l3-3 3 3"/><path d="M3 9.5v3.25c0 .4.35.75.75.75h8.5c.4 0 .75-.35.75-.75V9.5"/>',
    terminal: '<rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.25"/><path d="m4.5 6.25 2 1.75-2 1.75M8 10.25h3.5"/>',
    rdp: '<rect x="1.75" y="2.75" width="12.5" height="8.5" rx="1.25"/><path d="M5.75 14h4.5M8 11.25V14"/>',
    copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M10.75 5.25V3.5c0-.7-.55-1.25-1.25-1.25h-6c-.7 0-1.25.55-1.25 1.25v6c0 .7.55 1.25 1.25 1.25h1.75"/>',
    key: '<circle cx="10.5" cy="5.5" r="3.25"/><path d="M8.2 7.8 2.5 13.5M4.25 11.75l1.75 1.75M6 10l1.25 1.25"/>',
    clock: '<circle cx="8" cy="8" r="6"/><path d="M8 4.75V8l2.25 1.5"/>',
    eye: '<path d="M1.75 8S4 3.75 8 3.75 14.25 8 14.25 8 12 12.25 8 12.25 1.75 8 1.75 8Z"/><circle cx="8" cy="8" r="2"/>',
    play: '<path d="M5 3.25v9.5L12.5 8 5 3.25Z"/>',
    pause: '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
    refresh: '<path d="M13.25 8a5.25 5.25 0 1 1-1.55-3.7"/><path d="M13.25 2.5v2.75H10.5"/>',
    more: '<circle cx="3.5" cy="8" r=".9" fill="currentColor" stroke="none"/><circle cx="8" cy="8" r=".9" fill="currentColor" stroke="none"/><circle cx="12.5" cy="8" r=".9" fill="currentColor" stroke="none"/>',
    server: '<rect x="2.25" y="2.5" width="11.5" height="4.75" rx="1"/><rect x="2.25" y="8.75" width="11.5" height="4.75" rx="1"/><path d="M5 4.9h.01M5 11.1h.01"/>',
    user: '<circle cx="8" cy="5.5" r="2.75"/><path d="M2.75 13.75c.6-2.6 2.7-4 5.25-4s4.65 1.4 5.25 4"/>',
    scan: '<path d="M14.25 8A6.25 6.25 0 1 1 8 1.75"/><path d="M11 8a3 3 0 1 1-3-3"/><path d="m8 8 4.5-4.5"/>',
    wifi: '<path d="M1.75 6.25a8.8 8.8 0 0 1 12.5 0M4 8.6a5.6 5.6 0 0 1 8 0M6.25 10.9a2.45 2.45 0 0 1 3.5 0"/><path d="M8 13.25v.01"/>',
    cable: '<rect x="2.75" y="3.25" width="10.5" height="7" rx="1"/><path d="M5.75 10.25v3h4.5v-3M5.5 6.5v1M8 6.5v1M10.5 6.5v1"/>',
    'arrow-r': '<path d="M2.75 8h10.5M9.25 4l4 4-4 4"/>',
    panel: '<rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.25"/><path d="M9.5 2.75v10.5"/>',
    expand: '<path d="M9.5 2.25h4.25V6.5M13.75 2.25 9 7M6.5 13.75H2.25V9.5M2.25 13.75 7 9"/>',
    history: '<path d="M2.75 8a5.25 5.25 0 1 0 1.55-3.7"/><path d="M2.5 2.5v2.75h2.75M8 5.25V8l2 1.25"/>',
    move: '<path d="M2.25 8h8.5M7.75 5l3 3-3 3M13.75 3v10"/>',
    shield: '<path d="M8 1.75 13.25 3.6v4.1c0 3.1-2.15 5.45-5.25 6.55C4.9 13.15 2.75 10.8 2.75 7.7V3.6L8 1.75Z"/>',
    disk: '<path d="M2.25 9.5h11.5v3.75H2.25zM2.25 9.5 4.4 2.75h7.2l2.15 6.75"/><path d="M11 11.4h.01"/>',
    ext: '<path d="M9.25 2.25h4.5v4.5M13.75 2.25 7.5 8.5"/><path d="M11.75 9.5v3.75c0 .3-.25.5-.5.5h-8.5a.5.5 0 0 1-.5-.5v-8.5c0-.25.2-.5.5-.5H6.5"/>',
    info: '<circle cx="8" cy="8" r="6.25"/><path d="M8 7.25v4M8 4.75v.01"/>',
    layers: '<path d="M8 1.75 14.25 5 8 8.25 1.75 5 8 1.75Z"/><path d="m1.75 8 6.25 3.25L14.25 8M1.75 11 8 14.25 14.25 11"/>',
    folder: '<path d="M1.75 4.5c0-.4.35-.75.75-.75h3.6l1.5 1.5h5.9c.4 0 .75.35.75.75v6.25c0 .4-.35.75-.75.75h-11a.75.75 0 0 1-.75-.75Z"/>',
    columns: '<rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.25"/><path d="M6 2.75v10.5M10 2.75v10.5"/>',
    density: '<path d="M2.25 3.75h11.5M2.25 8h11.5M2.25 12.25h11.5"/>',
    proposal: '<circle cx="8" cy="8" r="6" stroke-dasharray="2.2 1.8"/><path d="M8 5.25v5.5M5.25 8h5.5"/>',
    link: '<path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2.1-2.1a2.75 2.75 0 0 0-3.9-3.9l-.8.8"/><path d="M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2.1 2.1a2.75 2.75 0 0 0 3.9 3.9l.8-.8"/>',
    pin: '<path d="M8 14.25s4.75-4.1 4.75-7.75a4.75 4.75 0 0 0-9.5 0c0 3.65 4.75 7.75 4.75 7.75Z"/><circle cx="8" cy="6.5" r="1.75"/>',
    bolt: '<path d="M9 1.75 3.5 9h4l-1 5.25L12.5 7h-4l.5-5.25Z"/>',
    router: '<rect x="1.75" y="8.25" width="12.5" height="5" rx="1"/><path d="M4.5 10.75h.01M7 10.75h.01M10.5 8.25 12.5 3M5.5 8.25 3.5 3"/>',
    vm: '<rect x="2.25" y="2.25" width="11.5" height="11.5" rx="1.5" stroke-dasharray="2.4 1.6"/><rect x="5" y="5" width="6" height="6" rx=".75"/>'
  };
  function injectSprite() {
    var s = '<svg xmlns="http://www.w3.org/2000/svg" style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true">';
    Object.keys(ICONS).forEach(function (k) { s += '<symbol id="i-' + k + '" viewBox="0 0 16 16">' + ICONS[k] + '</symbol>'; });
    s += '</svg>';
    document.body.insertAdjacentHTML('afterbegin', s);
  }
  function icon(name, cls) { return '<svg class="i ' + (cls || '') + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>'; }

  /* ---------------- Theme ---------------- */
  var root = document.documentElement;
  var THEME_KEY = 'tenko-theme';
  function storedTheme() { try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; } }
  function effectiveTheme() {
    var t = root.dataset.theme;
    if (t === 'light' || t === 'dark') return t;
    return window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function paintThemeButtons() {
    var t = root.dataset.theme || 'system';
    var label = { system: 'Theme: follows the system (' + effectiveTheme() + ')', light: 'Theme: light', dark: 'Theme: dark' }[t];
    document.querySelectorAll('[data-action="theme"]').forEach(function (b) {
      b.innerHTML = icon(t === 'system' ? 'system' : t === 'light' ? 'sun' : 'moon');
      b.title = label + '. Click to change.';
      b.setAttribute('aria-label', label);
    });
  }
  function cycleTheme() {
    var order = ['system', 'light', 'dark'];
    var cur = root.dataset.theme || 'system';
    var next = order[(order.indexOf(cur) + 1) % order.length];
    if (next === 'system') { delete root.dataset.theme; try { localStorage.removeItem(THEME_KEY); } catch (e) {} }
    else { root.dataset.theme = next; try { localStorage.setItem(THEME_KEY, next); } catch (e) {} }
    paintThemeButtons();
  }

  /* ---------------- Density ---------------- */
  var DENSITY_KEY = 'tenko-density';
  function setDensity(d) {
    if (d === 'compact') delete root.dataset.density; else root.dataset.density = d;
    try { localStorage.setItem(DENSITY_KEY, d); } catch (e) {}
    document.querySelectorAll('[data-density-set]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.densitySet === d)); });
  }

  /* ---------------- Toasts ---------------- */
  function toast(o) {
    var host = document.querySelector('.toasts');
    if (!host) { host = document.createElement('div'); host.className = 'toasts'; host.setAttribute('role', 'status'); document.body.appendChild(host); }
    var el = document.createElement('div');
    el.className = 'toast ' + (o.kind || '');
    var ic = o.kind === 'ok' ? 'check' : o.kind === 'bad' ? 'alert' : 'info';
    el.innerHTML = '<span style="color:var(--' + (o.kind === 'ok' ? 'job-done' : o.kind === 'bad' ? 'job-failed' : 'accent') + ')">' + icon(ic) + '</span>' +
      '<div><div class="t"></div></div><button class="icon-btn" style="width:22px;height:22px" aria-label="Dismiss">' + icon('x', 'xs') + '</button>' +
      (o.body ? '<div class="b"></div>' : '') + (o.actions ? '<div class="acts"></div>' : '');
    el.querySelector('.t').textContent = o.title;
    if (o.body) el.querySelector('.b').textContent = o.body;
    if (o.actions) o.actions.forEach(function (a) {
      var b = document.createElement(a.href ? 'a' : 'button');
      b.className = 'btn sm ' + (a.primary ? 'primary' : '');
      b.textContent = a.label; if (a.href) b.href = a.href;
      b.addEventListener('click', function () { if (a.onClick) a.onClick(); el.remove(); });
      el.querySelector('.acts').appendChild(b);
    });
    el.querySelector('button.icon-btn').addEventListener('click', function () { el.remove(); });
    host.appendChild(el);
    if (o.kind !== 'bad' && o.sticky !== true) setTimeout(function () { el.remove(); }, o.ms || 7000);
    return el;
  }

  /* ---------------- Command palette ---------------- */
  var PALETTE = [
    { g: 'Addresses and hosts', ic: 'ipam', t: '192.0.2.11', s: 'nas.example.test, static, LAN, DNS differs', href: 'host.html' },
    { g: 'Addresses and hosts', ic: 'ipam', t: '192.0.2.20', s: 'desk-01.example.test, reserved, LAN', href: 'host.html' },
    { g: 'Addresses and hosts', ic: 'ipam', t: '00-00-5E-00-53-2B', s: 'MAC of cam-door.example.test', href: 'host.html' },
    { g: 'Addresses and hosts', ic: 'layers', t: '198.51.100.0/24', s: 'IoT, VLAN 30, iot.example.test, 38 % used', href: 'shell-and-ipam.html' },
    { g: 'Actions', ic: 'move', t: 'Move selected hosts to network', s: 'Preview first, nothing changes until you confirm', k: ['M'] },
    { g: 'Actions', ic: 'plus', t: 'Claim next free address in 192.0.2.0/24', s: 'Next free: 192.0.2.22', k: ['N'] },
    { g: 'Actions', ic: 'scan', t: 'Scan 192.0.2.0/24 now', s: 'Passive refresh and port scan, runs as a job' },
    { g: 'Actions', ic: 'export', t: 'Export view as CSV', s: 'Columns and filters as shown' },
    { g: 'Go to', ic: 'dashboard', t: 'Dashboard', s: 'Cluster and node health', href: 'dashboard.html', k: ['G', 'B'] },
    { g: 'Go to', ic: 'ipam', t: 'IPAM', href: 'shell-and-ipam.html', k: ['G', 'I'] },
    { g: 'Go to', ic: 'topology', t: 'Topology', href: 'topology.html', k: ['G', 'T'] },
    { g: 'Go to', ic: 'jobs', t: 'Jobs', s: '1 running, 1 waiting for observation', href: 'move-job.html', k: ['G', 'J'] },
    { g: 'Go to', ic: 'settings', t: 'First-run wizard (mockup)', href: 'wizard.html' }
  ];
  var palSel = 0;
  function ensurePalette() {
    var ov = document.getElementById('palette');
    if (ov) return ov;
    ov = document.createElement('div');
    ov.id = 'palette'; ov.className = 'overlay';
    ov.innerHTML = '<div class="palette" role="dialog" aria-label="Command palette">' +
      '<div class="pin">' + icon('search') + '<input id="palette-input" placeholder="Jump to an address, host, MAC, prefix or command" autocomplete="off" spellcheck="false" aria-label="Search"><span class="kbd">Esc</span></div>' +
      '<div class="groups" id="palette-list" role="listbox"></div>' +
      '<div class="foot"><span><span class="kbd">↑</span><span class="kbd">↓</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">></span> commands only</span><span><span class="kbd">Tab</span> narrow by type</span></div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('mousedown', function (e) { if (e.target === ov) closePalette(); });
    var input = ov.querySelector('input');
    input.addEventListener('input', function () { palSel = 0; renderPalette(input.value); });
    input.addEventListener('keydown', function (e) {
      var items = ov.querySelectorAll('.it');
      if (e.key === 'ArrowDown') { palSel = Math.min(items.length - 1, palSel + 1); e.preventDefault(); markSel(items); }
      else if (e.key === 'ArrowUp') { palSel = Math.max(0, palSel - 1); e.preventDefault(); markSel(items); }
      else if (e.key === 'Enter') { var it = items[palSel]; if (it) it.click(); }
      else if (e.key === 'Escape') { closePalette(); }
    });
    return ov;
  }
  function markSel(items) { items.forEach(function (el, i) { el.setAttribute('aria-selected', String(i === palSel)); if (i === palSel) el.scrollIntoView({ block: 'nearest' }); }); }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function hi(text, q) {
    if (!q) return esc(text);
    var i = text.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return esc(text);
    return esc(text.slice(0, i)) + '<mark>' + esc(text.slice(i, i + q.length)) + '</mark>' + esc(text.slice(i + q.length));
  }
  function renderPalette(q) {
    var list = document.getElementById('palette-list');
    var cmdOnly = q.charAt(0) === '>';
    var qq = (cmdOnly ? q.slice(1) : q).trim();
    var rows = PALETTE.filter(function (p) {
      if (cmdOnly && p.g !== 'Actions') return false;
      if (!qq) return true;
      return (p.t + ' ' + (p.s || '')).toLowerCase().indexOf(qq.toLowerCase()) >= 0;
    });
    var html = '', lastG = '';
    rows.forEach(function (p, i) {
      if (p.g !== lastG) { html += '<div class="gh">' + p.g + '</div>'; lastG = p.g; }
      var mono = /^[0-9a-f:.\-\/]+$/i.test(p.t);
      html += '<a class="it" role="option" ' + (p.href ? 'href="' + p.href + '"' : 'href="#"') + ' aria-selected="' + (i === palSel) + '">' + icon(p.ic) +
        '<span class="' + (mono ? 'mono' : '') + '">' + hi(p.t, qq) + '</span>' + (p.s ? '<span class="s">' + hi(p.s, qq) + '</span>' : '') +
        (p.k ? '<span class="r">' + p.k.map(function (k) { return '<span class="kbd">' + k + '</span>'; }).join('') + '</span>' : '') + '</a>';
    });
    if (!rows.length) html = '<div class="empty" style="padding:24px"><h3>No match for “' + esc(qq) + '”</h3><p>Try part of an address (".41"), a MAC fragment ("53-2a") or a host name. Type <span class="kbd">></span> to search commands only.</p></div>';
    list.innerHTML = html;
    list.querySelectorAll('.it').forEach(function (el, i) {
      el.addEventListener('mousemove', function () { palSel = i; markSel(list.querySelectorAll('.it')); });
      el.addEventListener('click', function (e) {
        if (el.getAttribute('href') === '#') { e.preventDefault(); closePalette(); toast({ title: el.querySelector('span').textContent, body: 'In the product this runs the command. Mockup only.' }); }
      });
    });
  }
  function openPalette(prefill) {
    var ov = ensurePalette();
    ov.classList.add('open');
    var input = ov.querySelector('input');
    input.value = prefill || '';
    palSel = 0; renderPalette(input.value);
    setTimeout(function () { input.focus(); }, 0);
  }
  function closePalette() { var ov = document.getElementById('palette'); if (ov) ov.classList.remove('open'); }

  /* ---------------- Keyboard sheet ---------------- */
  var SHEET = [
    ['Anywhere', [['Command palette and search', ['Ctrl', 'K']], ['Keyboard shortcuts', ['?']], ['Go to dashboard', ['G', 'B']], ['Go to IPAM', ['G', 'I']], ['Go to DNS', ['G', 'D']], ['Go to DHCP', ['G', 'H']], ['Go to topology', ['G', 'T']], ['Go to jobs', ['G', 'J']], ['Go to settings', ['G', 'S']], ['Toggle theme', ['Shift', 'T']]]],
    ['Grids', [['Move focus', ['↑', '↓', '←', '→']], ['Also move focus', ['J', 'K']], ['Select row', ['Space']], ['Extend selection', ['Shift', '↑↓']], ['Select all in view', ['Ctrl', 'A']], ['Edit cell', ['Enter']], ['Cancel edit or clear selection', ['Esc']], ['Filter this view', ['/']], ['Open details panel', ['.']], ['Open as full page', ['Shift', 'Enter']]]],
    ['Changes', [['Move selection to network', ['M']], ['Set assignment mode', ['Shift', 'M']], ['Lock or unlock', ['L']], ['Claim next free address', ['N']], ['Undo last change', ['Ctrl', 'Z']], ['Open job panel', ['Shift', 'J']], ['Export CSV', ['Ctrl', 'Shift', 'E']]]],
    ['Tree and panels', [['Focus prefix tree', ['[']], ['Focus grid', [']']], ['Expand or collapse node', ['→', '←']], ['Close panel', ['Esc']]]]
  ];
  function openSheet() {
    var ov = document.getElementById('keysheet');
    if (!ov) {
      ov = document.createElement('div'); ov.id = 'keysheet'; ov.className = 'overlay';
      var html = '<div class="sheet" role="dialog" aria-label="Keyboard shortcuts"><h2>Keyboard shortcuts <button class="icon-btn" data-close aria-label="Close">' + icon('x') + '</button></h2><div class="cols">';
      SHEET.forEach(function (sec) {
        html += '<section><h3>' + sec[0] + '</h3><dl>';
        sec[1].forEach(function (r) { html += '<dt>' + r[0] + '</dt><dd>' + r[1].map(function (k) { return '<span class="kbd">' + k + '</span>'; }).join('') + '</dd>'; });
        html += '</dl></section>';
      });
      html += '</div><p class="muted" style="margin-top:20px;font-size:12px">Single-key shortcuts never fire while you type in a field. Every shortcut is listed in the command palette next to its command, so the palette is where you learn them.</p></div>';
      ov.innerHTML = html; document.body.appendChild(ov);
      ov.addEventListener('mousedown', function (e) { if (e.target === ov || e.target.closest('[data-close]')) ov.classList.remove('open'); });
    }
    ov.classList.add('open');
  }

  /* ---------------- Keyboard ---------------- */
  var NAV = { b: 'dashboard.html', i: 'shell-and-ipam.html', t: 'topology.html', j: 'move-job.html', s: 'wizard.html' };
  var chord = null, chordTimer = null;
  function typing(e) { var t = e.target; return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable); }
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
    if (e.key === 'Escape') { closePalette(); var ks = document.getElementById('keysheet'); if (ks) ks.classList.remove('open'); var n = document.getElementById('notes'); if (n && n.classList.contains('open') && !typing(e)) n.classList.remove('open'); }
    if (typing(e) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '?') { e.preventDefault(); openSheet(); return; }
    if (e.key === 'T' && e.shiftKey) { cycleTheme(); return; }
    if (chord === 'g') {
      clearTimeout(chordTimer); chord = null;
      var dest = NAV[e.key.toLowerCase()];
      if (dest) { location.href = dest; }
      else if (e.key === 'd' || e.key === 'h') { toast({ title: 'DNS and DHCP views are not part of this spike', body: 'They reuse the grid, filter bar and side panel shown in IPAM.' }); }
      return;
    }
    if (e.key === 'g') { chord = 'g'; chordTimer = setTimeout(function () { chord = null; }, 900); }
  });

  /* ---------------- Wiring ---------------- */
  function init() {
    injectSprite();
    paintThemeButtons();
    if (window.matchMedia) matchMedia('(prefers-color-scheme: dark)').addEventListener('change', paintThemeButtons);
    var d = null; try { d = localStorage.getItem(DENSITY_KEY); } catch (e) {}
    setDensity(d || 'compact');
    document.addEventListener('click', function (e) {
      var a = e.target.closest('[data-action]');
      if (a) {
        var act = a.dataset.action;
        if (act === 'theme') cycleTheme();
        else if (act === 'palette') openPalette();
        else if (act === 'keys') openSheet();
        else if (act === 'notes') {
          var n = document.getElementById('notes');
          if (n) { n.classList.toggle('open'); a.setAttribute('aria-expanded', String(n.classList.contains('open'))); }
        }
      }
      var ds = e.target.closest('[data-density-set]');
      if (ds) setDensity(ds.dataset.densitySet);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();

  window.tenko = { toast: toast, icon: icon, openPalette: openPalette, setDensity: setDensity };
})();
