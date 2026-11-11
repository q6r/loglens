/* loglens report view. Draws a loglens.summary/v1 document (the JSON island) in the Aurora layout of the
 * bundled UI kit: a rail with one destination per section, breadcrumbs, a Charts/Tables view switch,
 * context pills and a status bar. Everything that came from a log is handed to the kit's builders,
 * which use textContent only; this file never builds HTML from data. */
(function () {
  'use strict';

  const { el, fmt } = Aurora;
  const AC = window.AuroraCharts;
  Aurora.init();

  let data = null;
  try {
    data = JSON.parse(document.getElementById('report-data').textContent);
  } catch (err) {
    data = null;
  }
  if (!data) {
    const broken = Aurora.shell({ brand: { name: 'loglens', mark: 'terminal' }, crumbs: ['loglens', 'Report'], status: false });
    Aurora.empty(broken.container, {
      title: 'The report data could not be read',
      text: 'The data embedded in this file is damaged. Generate the report again with loglens html.',
      icon: 'alert',
    });
    return;
  }

  const T = data.totals;
  const META = data.meta;
  const LAT = data.latency || null;
  const hasTraffic = T.requests > 0;

  const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const REASONS = {
    200: 'OK', 201: 'Created', 204: 'No Content', 206: 'Partial Content', 301: 'Moved Permanently', 302: 'Found',
    304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect', 400: 'Bad Request', 401: 'Unauthorized',
    403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 408: 'Request Timeout', 413: 'Payload Too Large',
    429: 'Too Many Requests', 499: 'Client Closed Request', 500: 'Internal Server Error', 502: 'Bad Gateway',
    503: 'Service Unavailable', 504: 'Gateway Timeout',
  };
  const SEVERITY_RANK = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };
  const SECTIONS = [
    { id: 'overview', label: 'Overview', icon: 'home' },
    { id: 'traffic', label: 'Traffic', icon: 'activity' },
    { id: 'content', label: 'Content', icon: 'file-text' },
    { id: 'clients', label: 'Clients', icon: 'users' },
    { id: 'security', label: 'Security', icon: 'shield' },
    { id: 'data', label: 'Data', icon: 'database' },
  ];
  // Without requests only the overview (which says so) and the data section have anything to show.
  const sections = hasTraffic ? SECTIONS : SECTIONS.filter((s) => s.id === 'overview' || s.id === 'data');

  /* ── time and number helpers (everything is UTC, like the log) ── */
  const two = (n) => String(n).padStart(2, '0');
  const stamp = (d) => `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
  const utc = (iso) => stamp(new Date(iso));
  const spanText = (s) => (s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)}m` : s < 172800 ? `${Math.floor(s / 3600)}h ${two(Math.floor((s % 3600) / 60))}m` : `${Math.round(s / 86400)}d`);
  const latency = (v) => fmt.duration(v);
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const plural = (n, one, many) => `${fmt.int(n)} ${n === 1 ? one : many}`;
  const baseName = (path) => {
    const i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
    return i >= 0 && i < path.length - 1 ? path.slice(i + 1) : path;
  };

  function regroup(values, size) {
    const out = [];
    for (let i = 0; i < values.length; i += size) {
      let sum = 0;
      for (let j = i; j < Math.min(values.length, i + size); j++) sum += values[j];
      out.push(sum);
    }
    return out;
  }

  // Minute buckets for logs up to a day, hour buckets beyond (the same rule as the terminal dashboard).
  function pickSeries() {
    const { minute, hour } = data.timeline;
    const useHour = T.spanSeconds > 90000 || (minute.requests.length < 2 && hour.requests.length >= 2);
    return Object.assign({ label: useHour ? 'per hour' : 'per minute' }, useHour ? hour : minute);
  }

  /* ── the Aurora layout: rail, top bar, sub bar, status bar ── */
  const nSources = META.sources.length;
  const sourceTitle = nSources === 1 ? META.sources[0] : nSources === 0 ? 'Unnamed log' : plural(nSources, 'log file', 'log files');
  const sourceName = nSources === 1 ? baseName(META.sources[0]) : sourceTitle;
  const linesSeen = META.lines.total - META.lines.blank;
  const crumbsFor = (section) => [{ label: 'loglens', href: '#overview' }, sourceName, section.label];

  const pill = (name, text, title) => el('span', { class: 'a-pill', title: title || text }, Aurora.icon(name, { size: 14 }), el('span', { class: 'a-pill__label' }, text));
  const note = (name, text) => el('span', { class: 'a-statusbar__item' }, Aurora.icon(name, { size: 12 }), text);

  function periodText() {
    const from = utc(T.firstSeen);
    const to = utc(T.lastSeen);
    return `${from.slice(0, 10) === to.slice(0, 10) ? `${from} → ${to.slice(11)}` : `${from.slice(0, 10)} → ${to.slice(0, 10)}`} · ${spanText(T.spanSeconds)}`;
  }

  function contextPills() {
    const pills = [];
    if (hasTraffic) pills.push(pill('calendar', periodText(), `${utc(T.firstSeen)} to ${utc(T.lastSeen)} UTC`));
    pills.push(pill('list', `${fmt.int(T.requests)} requests`, `${fmt.int(META.lines.parsed)} of ${fmt.int(linesSeen)} lines parsed`));
    if (hasTraffic) pills.push(pill('database', `${fmt.bytes(T.bytes)} sent`, 'Response bytes sent to clients'));
    pills.push(pill('file-text', META.format, META.autoDetected ? 'Log format, detected automatically' : 'Log format, chosen with --format'));
    return pills;
  }

  // Every chart card registers here, so one switch in the sub bar can flip them all between chart and table.
  const cards = [];
  function setView(id, fromSwitch) {
    cards.forEach((card) => card.showTable(id === 'tables'));
    if (!fromSwitch && shell.views) shell.views.select(id, true);
  }

  const shell = Aurora.shell({
    brand: { name: 'loglens', href: '#overview', mark: 'terminal' },
    rail: [
      sections.map((s) => ({ id: s.id, label: s.label, icon: s.icon, href: `#${s.id}`, badge: s.id === 'security' ? data.findings.length : 0, active: s.id === 'overview' })),
      'spacer',
      [{ id: 'palette', label: 'Command palette', icon: 'command', cmdk: true }],
    ],
    crumbs: crumbsFor(sections[0]),
    views: hasTraffic ? {
      ariaLabel: 'Show charts or tables',
      active: 'charts',
      items: [{ id: 'charts', label: 'Charts', icon: 'bar-chart' }, { id: 'tables', label: 'Tables', icon: 'list' }],
      onChange: (id) => setView(id, true),
    } : null,
    subbarEnd: contextPills(),
    status: {
      start: [`loglens ${META.version}`, note('lock', 'No network requests')],
      end: [META.generatedAt ? `Generated ${utc(META.generatedAt)} UTC` : null, 'All times UTC'].filter(Boolean),
    },
  });
  const page = shell.container;

  /* ── layout helpers ── */
  const cell = (grid, span) => grid.appendChild(el('div', { class: `a-span-${span}` }));

  function section(id, title, lead) {
    const grid = el('div', { class: 'a-grid' });
    page.appendChild(el('section', { id, class: 'r-section', 'aria-labelledby': `${id}-title` },
      el('div', { class: 'r-heading a-reveal' }, el('h2', { class: 'a-h2', id: `${id}-title` }, title), lead ? el('p', { class: 'r-lead' }, lead) : null),
      grid));
    return grid;
  }

  const cardHead = (title, subtitle, actions) => el('div', { class: 'a-card__head' },
    el('div', null, el('div', { class: 'a-card__title' }, title), subtitle ? el('div', { class: 'a-card__sub' }, subtitle) : null),
    actions ? el('div', { class: 'a-card__actions' }, actions) : null);

  function chartCard(host, o) {
    const card = AC.card(host, o);
    cards.push(card);
    return card;
  }

  function barsCard(host, o) {
    chartCard(host, {
      title: o.title,
      subtitle: o.subtitle,
      render: (body) => AC.bars(body, {
        data: o.items.map((item, i) => ({ id: i, label: item.label, value: item.value, sub: item.sub })),
        orientation: 'horizontal',
        valueFormat: o.format || fmt.int,
        valueLabel: o.valueLabel || 'Requests',
        labelHeader: o.labelHeader,
        title: o.title,
        emptyText: o.empty,
      }),
    });
  }

  function overcountNote(item) {
    return item.overcount > 0 ? `may be over-counted by up to ${fmt.int(item.overcount)}` : null;
  }

  const copyJson = () => Aurora.copy(JSON.stringify(data, null, 2), { label: 'Summary JSON copied' });

  /* ── overview: the log, then the key figures ── */
  function overview() {
    const host = el('section', { id: 'overview', class: 'r-overview', 'aria-label': 'Overview' });
    page.appendChild(host);
    const covered = `${fmt.int(META.lines.parsed)} of ${fmt.int(linesSeen)} lines parsed`;
    host.appendChild(el('header', { class: 'a-pagehead a-reveal' },
      el('div', { class: 'r-head' },
        el('p', { class: 'a-eyebrow' }, 'Access log report'),
        el('h1', { class: 'a-h1 r-title', title: sourceTitle }, sourceTitle),
        el('p', { class: 'a-pagehead__sub' }, hasTraffic ? `${utc(T.firstSeen)} → ${utc(T.lastSeen)} UTC · ${spanText(T.spanSeconds)} · ${covered}` : covered)),
      el('div', { class: 'a-pagehead__actions' },
        el('button', { class: 'a-btn a-btn--sm', type: 'button', onclick: copyJson }, Aurora.icon('copy', { size: 14 }), 'Copy JSON'))));
    if (hasTraffic) keyFigures(host);
    else noRequests(host);
  }

  function noRequests(host) {
    const card = el('div', { class: 'a-card' });
    host.appendChild(card);
    const empty = Aurora.empty(card, { title: 'No requests parsed', text: 'The input held no requests.', icon: 'file' });
    if (META.lines.malformed > 0) {
      const text = empty.querySelector('.a-empty__text');
      text.textContent = '';
      text.append('Every line was rejected. Check the log format, or choose one with ', el('code', { class: 'a-inline-code r-nowrap' }, '--format'), ' (combined, common, json or caddy).');
    }
  }

  function keyFigures(host) {
    const grid = el('div', { class: 'a-grid r-kpis' });
    host.appendChild(grid);
    const tile = (cls, build) => build(grid.appendChild(el('div', { class: cls })));
    const s = pickSeries();
    const perRequest = T.requests ? T.bytes / T.requests : 0;
    tile('r-kpi-hero', (w) => Aurora.stat(w, {
      label: 'Requests',
      value: T.requests,
      format: 'compact',
      hero: true,
      hint: T.peakMinute ? `Peak ${fmt.int(T.peakMinute.requests)} in one minute, at ${utc(T.peakMinute.start)} UTC` : 'No requests parsed',
      spark: regroup(s.requests, Math.max(1, Math.ceil(s.requests.length / 48))),
    }));
    tile('r-kpi', (w) => Aurora.stat(w, {
      label: 'Unique visitors',
      value: T.uniqueIps,
      format: 'compact',
      hint: T.uniqueIpsExact ? 'Distinct client addresses' : 'Estimate, about ±1.6%',
    }));
    tile('r-kpi', (w) => Aurora.stat(w, {
      label: 'Bandwidth',
      value: T.bytes,
      format: 'bytes',
      hint: `${fmt.bytes(perRequest)} per request`,
    }));
    tile('r-kpi', (w) => Aurora.stat(w, {
      label: '5xx error rate',
      value: T.serverErrorRate,
      format: 'pct',
      digits: 1,
      hint: `4xx rate ${fmt.pct(T.clientErrorRate, 1)}`,
    }));
    tile('r-kpi', (w) => (LAT
      ? Aurora.stat(w, { label: 'Latency p95', value: LAT.p95, format: latency, hint: `p50 ${latency(LAT.p50)} · p99 ${latency(LAT.p99)}` })
      : Aurora.stat(w, { label: 'Latency', value: 0, format: () => 'n/a', hint: 'No request_time in this log' })));
  }

  /* ── traffic ── */
  function weekdayCells() {
    const hour = data.timeline.hour;
    const sums = WEEKDAYS.map(() => new Array(24).fill(0));
    hour.requests.forEach((count, i) => {
      const d = new Date((hour.start + i * 3600) * 1000);
      sums[(d.getUTCDay() + 6) % 7][d.getUTCHours()] += count;
    });
    const cells = [];
    sums.forEach((row, r) => row.forEach((value, c) => cells.push({ row: r, col: c, value })));
    return cells;
  }

  function statusCard(grid, span) {
    const body = el('div', { class: 'a-card__body r-status' });
    cell(grid, span).appendChild(el('div', { class: 'a-card a-reveal' }, cardHead('Status codes', 'Share of all requests, most frequent codes'), body));
    const colours = { '2xx': 'var(--good)', '3xx': 1, '4xx': 'var(--warn)', '5xx': 'var(--critical)' };
    Aurora.segbar(body, {
      tall: true,
      valueFormat: fmt.int,
      parts: data.status.classes.filter((c) => colours[c.class] !== undefined).map((c) => ({ name: c.class, value: c.count, color: colours[c.class] })),
    });
    Aurora.table(body, {
      dense: true,
      caption: 'Most frequent status codes',
      sort: { key: 'count', dir: 'desc' },
      columns: [
        { key: 'code', label: 'Code', mono: true, sortable: false },
        { key: 'reason', label: 'Meaning', sortable: false },
        { key: 'count', label: 'Requests', align: 'right', sortable: false, format: (v) => fmt.int(v) },
        { key: 'share', label: 'Share', align: 'right', sortable: false, format: (v) => fmt.pct(v, 1) },
      ],
      rows: data.status.codes.slice(0, 8).map((c) => ({ code: c.code, reason: REASONS[c.code] || '', count: c.count, share: T.requests ? c.count / T.requests : 0 })),
    });
  }

  function spikesCard(host) {
    const card = el('div', { class: 'a-card a-card--flush a-reveal' }, cardHead('5xx spikes', 'Minutes where server errors are a statistical outlier'));
    host.appendChild(card);
    Aurora.table(card, {
      dense: true,
      caption: '5xx spikes',
      sort: { key: 'errors', dir: 'desc' },
      columns: [
        { key: 'window', label: 'Window (UTC)', sortable: false },
        { key: 'errors', label: '5xx', align: 'right', format: (v) => fmt.int(v) },
        { key: 'rate', label: 'Of requests', align: 'right', format: (v) => fmt.pct(v, 0) },
        { key: 'peak', label: 'Peak/min', align: 'right', format: (v) => fmt.int(v) },
      ],
      rows: data.errorSpikes.map((sp) => ({
        window: `${utc(sp.from)} → ${utc(sp.to).slice(11)}`,
        errors: sp.serverErrors,
        rate: sp.rate,
        peak: sp.peak,
      })),
    });
  }

  function traffic() {
    const s = pickSeries();
    const grid = section('traffic', 'Traffic', 'When and how requests arrive. All times are UTC; every chart has a table view for exact values.');
    const hasTimeline = s.requests.length >= 2;
    if (!hasTimeline) {
      const card = el('div', { class: 'a-card' });
      cell(grid, 12).appendChild(card);
      Aurora.empty(card, { title: 'Not enough data for a timeline', text: 'The log covers fewer than two time buckets.', icon: 'clock' });
    } else {
      chartCard(cell(grid, 12), {
        title: 'Requests over time',
        subtitle: `Requests ${s.label}, UTC`,
        render: (body) => AC.line(body, {
          series: [{ id: 'requests', name: 'Requests', color: 1, values: s.requests.map((y, i) => ({ x: (s.start + i * s.step) * 1000, y })) }],
          x: { type: 'time', utc: true, label: 'Time (UTC)' },
          area: true,
          height: 280,
          title: 'Requests over time',
          ariaLabel: `Requests ${s.label}`,
        }),
      });
      const group = Math.max(1, Math.ceil(s.requests.length / 48));
      const longSpan = s.step >= 3600 || T.spanSeconds > 86400;
      // Axis labels longer than nine characters are cut by the chart, so a bar is named "11-09 06h" (its first hour).
      const categories = regroup(s.requests, group).map((_, i) => {
        const d = new Date((s.start + i * group * s.step) * 1000);
        return longSpan ? `${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(d.getUTCHours())}h` : `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
      });
      chartCard(cell(grid, 7), {
        title: 'Status classes over time',
        subtitle: `Requests ${s.label}, stacked`,
        render: (body) => AC.stacked(body, {
          categories,
          series: [['2xx', 's2xx', 'good'], ['3xx', 's3xx', 1], ['4xx', 's4xx', 'warn'], ['5xx', 's5xx', 'critical']]
            .map(([name, key, color]) => ({ id: name, name, color, values: regroup(s[key], group) })),
          height: 300,
          title: 'Status classes over time',
        }),
      });
    }
    statusCard(grid, hasTimeline ? 5 : 12);

    if (data.timeline.hour.requests.length >= 24) {
      chartCard(cell(grid, 12), {
        title: 'When traffic arrives',
        subtitle: 'Requests by weekday and hour of day, UTC',
        render: (body) => AC.heatmap(body, {
          kind: 'matrix',
          rows: WEEKDAYS,
          cols: Array.from({ length: 24 }, (_, i) => two(i)),
          cells: weekdayCells(),
          unit: 'requests',
          rowLabel: 'Weekday',
          colLabel: 'Hour (UTC)',
          title: 'When traffic arrives',
        }),
      });
    }

    // With request times, the response percentiles and the 5xx spikes share the left column and the
    // slowest endpoints take the right one; without them the spikes (if any) get a row of their own.
    if (LAT) {
      const left = cell(grid, 5);
      left.classList.add('r-stack');
      barsCard(left, {
        title: 'Response time',
        subtitle: `${fmt.int(LAT.count)} requests with a request_time`,
        valueLabel: 'Time',
        labelHeader: 'Percentile',
        format: latency,
        items: ['p50', 'p90', 'p95', 'p99', 'max'].map((key) => ({
          label: key,
          value: LAT[key],
          sub: LAT.upstream ? `upstream ${latency(LAT.upstream[key])}` : null,
        })),
      });
      if (data.errorSpikes.length) spikesCard(left);
      barsCard(cell(grid, 7), {
        title: 'Slowest endpoints',
        subtitle: 'Average time per request, endpoints with enough timed requests',
        valueLabel: 'Average time',
        labelHeader: 'Path',
        format: latency,
        items: LAT.slowest.map((p) => ({ label: p.path, value: p.avgMs, sub: `max ${latency(p.maxMs)} · ${plural(p.count, 'timed request', 'timed requests')}` })),
        empty: 'No endpoint has enough timed requests',
      });
    } else if (data.errorSpikes.length) {
      spikesCard(cell(grid, 12));
    }
  }

  /* ── content, clients ── */
  function content() {
    const grid = section('content', 'Content', 'What is requested. Ranked lists come from bounded-memory sketches, so on very busy logs a count can be slightly over-estimated.');
    barsCard(cell(grid, 6), {
      title: 'Top paths',
      subtitle: 'Requests by URL path, query string removed',
      labelHeader: 'Path',
      items: data.paths.map((p) => ({ label: p.path, value: p.count, sub: [`${fmt.bytes(p.bytes)} sent`, `${fmt.int(p.errors)} errors`, overcountNote(p)].filter(Boolean).join(' · ') })),
      empty: 'No requests',
    });
    barsCard(cell(grid, 6), {
      title: 'Top referrers',
      subtitle: 'Requests by referring host',
      labelHeader: 'Host',
      items: data.referrers.map((r) => ({ label: r.host, value: r.count, sub: overcountNote(r) })),
      empty: 'No referrers in this log',
    });
    barsCard(cell(grid, 6), {
      title: 'Not found',
      subtitle: 'Paths answered with 404',
      labelHeader: 'Path',
      items: data.errorPaths.notFound.map((p) => ({ label: p.path, value: p.count, sub: overcountNote(p) })),
      empty: 'No 404 responses',
    });
    barsCard(cell(grid, 6), {
      title: 'Server errors',
      subtitle: 'Paths answered with 5xx',
      labelHeader: 'Path',
      items: data.errorPaths.serverErrors.map((p) => ({ label: p.path, value: p.count, sub: overcountNote(p) })),
      empty: 'No 5xx responses',
    });
  }

  function clients() {
    const grid = section('clients', 'Clients', 'Who is asking. Addresses are shown as logged: behind a proxy or CDN they are the proxy\'s unless the log format records the real client.');
    const body = el('div', { class: 'a-card__body a-stack' });
    cell(grid, 12).appendChild(el('div', { class: 'a-card a-reveal' }, cardHead('Humans, bots and tools', 'Requests by user-agent class'), body));
    const classColours = { human: 1, bot: 2, tool: 3, scanner: 4, unknown: 'var(--chart-muted)' };
    Aurora.segbar(body, {
      tall: true,
      valueFormat: fmt.int,
      parts: data.agents.classes.map((c) => ({ name: cap(c.class), value: c.count, color: classColours[c.class] })),
    });
    body.appendChild(el('p', { class: 'r-hint' },
      'Classes are decided from the user-agent string, which clients choose freely: treat them as a guide, not as proof.'));

    barsCard(cell(grid, 6), {
      title: 'Top clients',
      subtitle: 'Requests by client address',
      labelHeader: 'Address',
      items: data.clients.map((c) => ({ label: c.ip, value: c.count, sub: `${fmt.bytes(c.bytes)} sent · busiest minute ${fmt.int(c.peakPerMinute)} requests · ${plural(c.errors, 'error', 'errors')}` })),
      empty: 'No clients',
    });
    barsCard(cell(grid, 6), {
      title: 'Browsers, bots and tools',
      subtitle: 'Requests by user-agent family',
      labelHeader: 'Family',
      items: data.agents.families.map((f) => ({ label: f.name, value: f.count, sub: `${cap(f.class)} · ${fmt.pct(f.share, 1)} of requests` })),
      empty: 'No user agents',
    });
  }

  /* ── security ── */
  function openFinding(f) {
    const sev = Aurora.severity(f.severity);
    const evidence = el('div');
    Aurora.code(evidence, f.evidence.join('\n'), { wrap: true });
    Aurora.dialog({
      title: f.title,
      drawer: true,
      size: 'lg',
      content: el('div', { class: 'a-stack' },
        el('div', { class: 'a-row' }, Aurora.badge(sev.label, { kind: sev.kind }), el('span', { class: 'a-muted' }, plural(f.count, 'matching request', 'matching requests'))),
        f.ips.length ? el('div', { class: 'r-block' }, el('div', { class: 'a-eyebrow' }, 'Clients'), el('div', { class: 'r-tags' }, f.ips.map((ip) => el('span', { class: 'a-tag' }, ip)))) : null,
        el('div', { class: 'r-block' }, el('div', { class: 'a-eyebrow' }, 'Evidence'), evidence),
        el('div', { class: 'r-block' }, el('div', { class: 'a-eyebrow' }, 'Limitations'), el('ul', { class: 'r-list' }, f.limitations.map((text) => el('li', text))))),
      actions: [{ label: 'Close', kind: 'ghost' }],
    });
  }

  function security() {
    const grid = section('security', 'Security', 'Heuristic findings: patterns in the request log, not proof of compromise. Select a finding for its evidence and limitations.');
    const host = cell(grid, 12);
    if (!data.findings.length) {
      const card = el('div', { class: 'a-card' });
      host.appendChild(card);
      Aurora.empty(card, { title: 'No suspicious patterns matched', text: 'The scanners, probes, injection signatures and brute-force heuristics found nothing in this log.', icon: 'shield' });
      return;
    }
    const perSeverity = {};
    data.findings.forEach((f) => { perSeverity[f.severity] = (perSeverity[f.severity] || 0) + 1; });
    const summary = ['critical', 'high', 'medium', 'low', 'info'].filter((key) => perSeverity[key]).map((key) => {
      const sev = Aurora.severity(key);
      return Aurora.badge(`${perSeverity[key]} ${sev.label}`, { kind: sev.kind });
    });
    const card = el('div', { class: 'a-card a-card--flush a-reveal r-findings' }, cardHead(plural(data.findings.length, 'finding', 'findings'), 'Most severe first', summary));
    host.appendChild(card);
    Aurora.table(card, {
      caption: 'Security findings',
      sort: { key: 'rank', dir: 'desc' },
      onRowClick: (row) => openFinding(row.finding),
      columns: [
        { key: 'rank', label: 'Severity', width: '130px', format: (_, row) => { const sev = Aurora.severity(row.finding.severity); return Aurora.badge(sev.label, { kind: sev.kind }); } },
        { key: 'title', label: 'Finding' },
        { key: 'count', label: 'Matches', align: 'right', format: (v) => fmt.int(v) },
        { key: 'clients', label: 'Clients', mono: true },
      ],
      rows: data.findings.map((f) => ({
        rank: SEVERITY_RANK[f.severity] || 0,
        title: f.title,
        count: f.count,
        clients: f.ips.slice(0, 2).join(', ') + (f.ips.length > 2 ? ` +${f.ips.length - 2}` : ''),
        finding: f,
      })),
    });
  }

  /* ── data quality ── */
  function quality() {
    const grid = section('data', 'Data', 'What this report is based on.');
    const L = META.lines;
    const win = META.window || {};
    const facts = [
      ['Sources', META.sources.length ? META.sources.join(', ') : null],
      ['Format', `${META.format}${META.autoDetected ? ' (auto-detected)' : ''}`],
      ['Lines', `${fmt.int(L.parsed)} parsed of ${fmt.int(linesSeen)} (${fmt.int(L.malformed)} malformed, ${fmt.int(L.outsideWindow)} outside the time window)`],
      ['Time window', win.from || win.to ? `${win.from ? utc(win.from) : 'start'} to ${win.to ? utc(win.to) : 'end'} UTC` : 'None: the whole log'],
      ['Visitors', T.uniqueIpsExact ? 'Exact count of distinct addresses' : 'HyperLogLog estimate, about ±1.6%'],
      ['Ranked lists', `Space-Saving sketches that track ${fmt.int(META.limits.topCapacity)} keys each`],
      ['Generated', META.generatedAt ? `${utc(META.generatedAt)} UTC by loglens ${META.version}` : `loglens ${META.version}`],
      ['Network', 'None: this is one self-contained file and it makes no requests'],
    ];
    const body = el('div', { class: 'a-card__body' });
    cell(grid, 7).appendChild(el('div', { class: 'a-card a-reveal' }, cardHead('Report facts'), body));
    Aurora.kv(body, facts);

    const samples = el('div', { class: 'a-card__body a-stack' });
    cell(grid, 5).appendChild(el('div', { class: 'a-card a-reveal' }, cardHead('Rejected lines', 'First examples, untrusted text shown inert'), samples));
    if (META.malformedSamples.length) {
      Aurora.code(samples, META.malformedSamples.map((m) => `line ${m.line}: ${m.reason}: ${m.preview}`).join('\n'), { wrap: true });
    } else {
      Aurora.empty(samples, { title: 'Every line was understood', text: 'No malformed lines in this log.', icon: 'check-circle' });
    }
  }

  /* ── assemble ── */
  overview();
  if (hasTraffic) {
    traffic();
    content();
    clients();
    security();
  }
  quality();
  Aurora.reveal(page);

  /* ── navigation: scroll-spy for the rail and the breadcrumbs, and the command palette ── */
  const goTo = (id) => {
    const target = document.getElementById(id);
    if (target) target.scrollIntoView({ behavior: Aurora.reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  };

  let current = '';
  function follow() {
    const line = shell.chrome.offsetHeight + window.innerHeight * 0.25;
    const atEnd = window.scrollY > 0 && window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
    let index = 0;
    sections.forEach((s, i) => {
      const node = document.getElementById(s.id);
      if (node && node.getBoundingClientRect().top < line) index = i;
    });
    if (atEnd) index = sections.length - 1;
    const now = sections[index];
    if (now.id === current) return;
    current = now.id;
    shell.setActive(now.id);
    shell.setCrumbs(crumbsFor(now));
  }
  window.addEventListener('scroll', Aurora.throttle(follow, 80), { passive: true });
  window.addEventListener('resize', Aurora.debounce(follow, 120));
  follow();

  const commands = sections.map((s) => ({ id: `go-${s.id}`, label: `Go to ${s.label}`, group: 'Navigate', hint: 'section', run: () => goTo(s.id) }));
  data.findings.forEach((f, i) => {
    const sev = Aurora.severity(f.severity);
    commands.push({ id: `finding-${i}`, label: f.title, group: 'Findings', hint: sev.label, keywords: 'security finding', run: () => openFinding(f) });
  });
  if (hasTraffic) {
    commands.push(
      { id: 'view-charts', label: 'Show charts', group: 'Actions', keywords: 'view graphs', run: () => setView('charts') },
      { id: 'view-tables', label: 'Show tables', group: 'Actions', keywords: 'view data exact values', run: () => setView('tables') },
    );
  }
  commands.push(
    { id: 'theme', label: 'Toggle light / dark theme', group: 'Actions', keywords: 'appearance mode', run: () => Aurora.theme.toggle() },
    { id: 'copy-json', label: 'Copy summary JSON', group: 'Actions', keywords: 'export data', run: copyJson },
    { id: 'print', label: 'Print or save as PDF', group: 'Actions', run: () => window.print() },
  );
  Aurora.cmdk.register(commands);
}());
