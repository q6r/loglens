--- Terminal dashboard: turns a `loglens.summary/v1` table into a string.
--
-- `render(summary, opts)` is a PURE function (no I/O, no clock, no globals), so frames can be
-- tested byte for byte. It adapts to the requested width, uses unicode blocks for sparklines and
-- bars (or plain ASCII with `ascii = true`) and ANSI colours unless `color = false`.
--
-- Everything that came from the log (paths, addresses, user agents, evidence lines) goes through
-- `loglens.util.defang`, so a hostile log can neither inject terminal escape sequences nor smuggle
-- live markup or shell syntax into the output.
-- @module loglens.render.terminal
local time = require("loglens.time")
local util = require("loglens.util")

local M = {}

local concat, sort = table.concat, table.sort
local ceil, floor, max, min = math.ceil, math.floor, math.max, math.min
local find, format, gsub, rep = string.find, string.format, string.gsub, string.rep
local defang, pad_left, pad_right, truncate = util.defang, util.pad_left, util.pad_right, util.truncate
local visible_width = util.visible_width

local GLYPHS = {
  unicode = {
    full = "\u{2588}",
    partials = { "\u{258F}", "\u{258E}", "\u{258D}", "\u{258C}", "\u{258B}", "\u{258A}", "\u{2589}" },
    spark = { "\u{2581}", "\u{2582}", "\u{2583}", "\u{2584}", "\u{2585}", "\u{2586}", "\u{2587}",
      "\u{2588}" },
    mono_classes = { "\u{00B7}", "\u{2588}", "\u{2593}", "\u{2592}", "\u{2591}" },
    dot = "\u{00B7}",
    arrow = "\u{2192}",
    ellipsis = "\u{2026}",
    approx = "\u{2248} ",
    pulse = { "\u{25CF}", "\u{25CB}" },
    spinner = { "\u{280B}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283C}", "\u{2834}", "\u{2826}",
      "\u{2827}", "\u{2807}", "\u{280F}" },
    ok = "\u{2713}",
    warn = "\u{26A0}",
  },
  ascii = {
    full = "#",
    partials = {},
    spark = { ".", ":", "-", "=", "+", "*", "#", "@" },
    mono_classes = { ".", "#", "=", "-", "'" },
    dot = "-",
    arrow = "->",
    ellipsis = "...",
    approx = "~",
    pulse = { "*", "o" },
    spinner = { "|", "/", "-", "\\" },
    ok = "ok",
    warn = "!",
  },
}

local BADGES = {
  critical = { text = "CRIT", bg = 203 },
  high = { text = "HIGH", bg = 208 },
  medium = { text = "MED ", bg = 221 },
  low = { text = "LOW ", bg = 110 },
  info = { text = "INFO", bg = 245 },
}

local CLASS_COLOURS = { 245, 78, 75, 221, 203 }
local AGENT_COLOURS = { human = 78, bot = 81, tool = 221, scanner = 203, unknown = 245 }

local function make_style(enabled)
  local function wrap(code)
    if not enabled then
      return function(text)
        return text
      end
    end
    return function(text)
      return "\27[" .. code .. "m" .. text .. "\27[0m"
    end
  end
  local style = {
    enabled = enabled,
    bold = wrap("1"),
    dim = wrap("2"),
    muted = wrap("38;5;245"),
    accent = wrap("1;38;5;81"),
    good = wrap("38;5;78"),
    warn = wrap("38;5;221"),
    critical = wrap("38;5;203"),
    bar = wrap("38;5;81"),
  }
  function style.colour(code)
    return wrap("38;5;" .. code)
  end
  function style.badge(severity)
    local badge = BADGES[severity] or BADGES.info
    if not enabled then
      return "[" .. badge.text .. "]"
    end
    return format("\27[1;38;5;16;48;5;%dm %s \27[0m", badge.bg, badge.text)
  end
  return style
end

---------------------------------------------------------------------------------------------
-- Primitives
---------------------------------------------------------------------------------------------

-- Full-height value for a sparkline: the largest sample, or for longer series the 98th percentile
-- of the non-zero samples, so one extreme minute does not flatten everything else (outliers are
-- clipped to full height).
local function scale_peak(samples)
  local positives = {}
  for _, value in ipairs(samples) do
    if value > 0 then
      positives[#positives + 1] = value
    end
  end
  if #positives == 0 then
    return 0
  end
  sort(positives)
  if #positives < 50 then
    return positives[#positives]
  end
  return positives[ceil(0.98 * #positives)]
end

-- Sparkline of at most `width` columns: values are resampled by maximum; zero stays blank so
-- gaps stay visible.
local function sparkline(values, width, glyphs)
  local n = #values
  if n == 0 or width < 1 then
    return ""
  end
  local count = min(n, width)
  local samples = {}
  for c = 1, count do
    local first = (c - 1) * n // count + 1
    local last = max(first, c * n // count)
    local best = 0
    for i = first, last do
      best = max(best, values[i])
    end
    samples[c] = best
  end
  local peak = scale_peak(samples)
  local out = {}
  for c = 1, count do
    out[c] = (samples[c] <= 0 or peak <= 0) and " "
      or glyphs.spark[max(1, min(8, ceil(samples[c] / peak * 8)))]
  end
  return concat(out)
end

-- Horizontal bar of exactly `width` columns (eighth-block resolution in unicode mode).
local function bar(value, peak, width, glyphs)
  if width < 1 then
    return ""
  end
  if value <= 0 or peak <= 0 then
    return rep(" ", width)
  end
  if #glyphs.partials == 0 then
    local cells = max(1, min(width, floor(value / peak * width + 0.5)))
    return rep(glyphs.full, cells) .. rep(" ", width - cells)
  end
  local eighths = max(1, min(width * 8, floor(value / peak * width * 8 + 0.5)))
  local full, remainder = eighths // 8, eighths % 8
  local text, used = rep(glyphs.full, full), full
  if remainder > 0 then
    text, used = text .. glyphs.partials[remainder], used + 1
  end
  return text .. rep(" ", width - used)
end

-- Splits `width` cells between counts (largest remainder); a non-zero count keeps at least one
-- cell whenever there is room.
local function allocate(counts, width)
  local total = 0
  for _, count in ipairs(counts) do
    total = total + count
  end
  local cells = {}
  for i = 1, #counts do
    cells[i] = 0
  end
  if total == 0 or width < 1 then
    return cells
  end
  local remainders, used = {}, 0
  for i, count in ipairs(counts) do
    local exact = count / total * width
    cells[i] = floor(exact)
    used = used + cells[i]
    remainders[#remainders + 1] = { index = i, fraction = exact - cells[i] }
  end
  sort(remainders, function(a, b)
    if a.fraction ~= b.fraction then
      return a.fraction > b.fraction
    end
    return a.index < b.index
  end)
  for k = 1, width - used do
    local item = remainders[(k - 1) % #remainders + 1]
    cells[item.index] = cells[item.index] + 1
  end
  for i, count in ipairs(counts) do
    if count > 0 and cells[i] == 0 then
      local donor, donor_cells = nil, 1
      for j = 1, #cells do
        if cells[j] > donor_cells then
          donor, donor_cells = j, cells[j]
        end
      end
      if donor then
        cells[donor], cells[i] = cells[donor] - 1, 1
      end
    end
  end
  return cells
end

-- Places blocks (arrays of lines) side by side; `widths[i]` is the width of column i.
local function columns(blocks, widths, gap)
  local height = 0
  for _, block in ipairs(blocks) do
    height = max(height, #block)
  end
  local out = {}
  for row = 1, height do
    local parts = {}
    for i, block in ipairs(blocks) do
      local text = block[row] or ""
      parts[i] = i < #blocks and pad_right(text, widths[i]) or text
    end
    out[row] = concat(parts, rep(" ", gap))
  end
  return out
end

local function fit(ctx, text, cols)
  return defang(text, cols, ctx.g.ellipsis)
end

-- Trailing blanks inside styled text would survive `finish`, so they are cut before styling.
local function trim_end(text)
  return (gsub(text, " +$", ""))
end

-- Packs already styled items into lines of at most `room` columns, `gap` blanks apart.
local function flow(items, room, gap)
  local lines, row, used = {}, {}, 0
  for _, item in ipairs(items) do
    local width = visible_width(item)
    if #row > 0 and used + gap + width > room then
      lines[#lines + 1] = concat(row, rep(" ", gap))
      row, used = {}, 0
    end
    row[#row + 1] = item
    used = used + width + (#row > 1 and gap or 0)
  end
  if #row > 0 then
    lines[#lines + 1] = concat(row, rep(" ", gap))
  end
  return lines
end

---------------------------------------------------------------------------------------------
-- Sections
---------------------------------------------------------------------------------------------

local function duration_text(seconds)
  if seconds < 90 then
    return format("%ds", seconds)
  elseif seconds < 5400 then
    return format("%dm", floor(seconds / 60 + 0.5))
  elseif seconds < 172800 then
    local hours, minutes = seconds // 3600, (seconds % 3600) // 60
    return minutes == 0 and format("%dh", hours) or format("%dh %02dm", hours, minutes)
  end
  return format("%dd", floor(seconds / 86400 + 0.5))
end

local function period_text(ctx, totals)
  local first, last = time.parse_iso(totals.firstSeen), time.parse_iso(totals.lastSeen)
  local to = (first // 86400 == last // 86400) and time.format_clock(last) or time.format_datetime(last)
  return format("%s %s %s UTC (%s)", time.format_datetime(first), ctx.g.arrow, to,
    duration_text(totals.spanSeconds))
end

-- "loglens  * LIVE | +37 new  access.log - combined - 2026-11-10 14:00 -> 14:11 UTC (12m)". Only the
-- file name and format come from outside, so only they are defanged; the rest is built from
-- glyphs and numbers. The line never reaches the last column, however long the state text is.
local function header(ctx, summary, opts, out)
  local s, g = ctx.style, ctx.g
  local lead = " " .. s.accent("loglens")
  local live = opts.live
  if live then
    local frame = opts.frame or 0
    local state
    if live.status == "rotated" then
      state = "log rotated, following the new file"
    elseif live.status == "waiting" then
      state = "waiting for the file"
    else
      state = format("+%s new", util.fmt_int(live.new_lines or 0))
    end
    lead = lead .. "  " .. s.good(g.pulse[frame % #g.pulse + 1] .. " LIVE") .. " "
      .. s.accent(g.spinner[frame % #g.spinner + 1]) .. " "
    lead = lead .. s.muted(truncate(state, ctx.width - visible_width(lead) - 1, g.ellipsis))
  end
  local meta = summary.meta
  local bits = {}
  if #meta.sources > 0 then
    bits[1] = #meta.sources == 1 and defang(meta.sources[1], ctx.width, g.ellipsis)
      or format("%d files", #meta.sources)
  end
  bits[#bits + 1] = defang(meta.format, ctx.width, g.ellipsis)
  if summary.totals.firstSeen then
    bits[#bits + 1] = period_text(ctx, summary.totals)
  end
  local room = ctx.width - visible_width(lead) - 3
  if room >= 8 then
    lead = lead .. "  " .. s.muted(truncate(concat(bits, " " .. g.dot .. " "), room, g.ellipsis))
  end
  out[#out + 1] = lead
  out[#out + 1] = ""
end

local function kpi_cells(ctx, summary)
  local s = ctx.style
  local totals, latency = summary.totals, summary.latency
  local error_style = s.good
  if totals.serverErrorRate >= 0.05 then
    error_style = s.critical
  elseif totals.serverErrorRate >= 0.01 then
    error_style = s.warn
  end
  local per_request = totals.requests > 0 and totals.bytes / totals.requests or 0
  local visitors = (totals.uniqueIpsExact and "" or ctx.g.approx) .. util.fmt_int(totals.uniqueIps)
  local rate = totals.avgRps >= 10 and format("%.0f/s", totals.avgRps) or format("%.2f/s", totals.avgRps)
  return {
    { "REQUESTS", s.bold(util.fmt_int(totals.requests)),
      format("peak %s/min", util.fmt_int(totals.peakMinute.requests)) },
    { "BANDWIDTH", s.bold(util.fmt_bytes(totals.bytes)), "avg " .. util.fmt_bytes(per_request) },
    { "VISITORS", s.bold(visitors), "unique IPs" },
    { "AVG RATE", s.bold(rate), "over " .. duration_text(totals.spanSeconds) },
    { "5XX RATE", error_style(s.bold(util.fmt_pct(totals.serverErrorRate))),
      "4xx " .. util.fmt_pct(totals.clientErrorRate) },
    latency and { "LATENCY P99", s.bold(util.fmt_duration_ms(latency.p99)),
      "p50 " .. util.fmt_duration_ms(latency.p50) }
      or { "LATENCY P99", s.muted("n/a"), "no request_time" },
  }
end

local function kpis(ctx, summary, out)
  local s = ctx.style
  local cells = kpi_cells(ctx, summary)
  local per_row = ctx.cw >= 84 and 6 or (ctx.cw >= 48 and 3 or 2)
  local cell_width = ctx.cw // per_row
  for first = 1, #cells, per_row do
    local labels, values, subs = {}, {}, {}
    for i = first, min(first + per_row - 1, #cells) do
      local cell, slot = cells[i], i - first + 1
      labels[slot] = pad_right(s.muted(cell[1]), cell_width)
      values[slot] = pad_right(cell[2], cell_width)
      subs[slot] = pad_right(s.dim(truncate(cell[3], cell_width - 1, ctx.g.ellipsis)), cell_width)
    end
    out[#out + 1] = " " .. concat(labels)
    out[#out + 1] = " " .. concat(values)
    out[#out + 1] = " " .. concat(subs)
    out[#out + 1] = ""
  end
end

local function traffic(ctx, summary, out)
  local s, g = ctx.style, ctx.g
  local timeline = summary.timeline
  local series, unit, label = timeline.minute, "min", "per minute"
  if summary.totals.spanSeconds > 90000 or (#series.requests < 2 and #timeline.hour.requests >= 2) then
    series, unit, label = timeline.hour, "hour", "per hour"
  end
  local n = #series.requests
  if n == 0 then
    return
  end
  local gutter = 5
  local room = ctx.cw - gutter
  local peak_value, peak_index, errors_total = 0, 1, 0
  for i, value in ipairs(series.requests) do
    if value > peak_value then
      peak_value, peak_index = value, i
    end
  end
  for _, value in ipairs(series.s5xx) do
    errors_total = errors_total + value
  end
  local first = series.start
  local last = first + (n - 1) * series.step
  local peak_at = first + (peak_index - 1) * series.step
  local caption = format("requests %s, peak %s/%s at %s", label, util.fmt_int(peak_value), unit,
    time.format_clock(peak_at))
  out[#out + 1] = " " .. s.accent("TRAFFIC") .. "  " .. s.muted(fit(ctx, caption, ctx.cw - 10))
  out[#out + 1] = " " .. s.muted(pad_right("req", gutter))
    .. s.bar(trim_end(sparkline(series.requests, room, g)))
  if errors_total > 0 then
    out[#out + 1] = " " .. s.muted(pad_right("5xx", gutter))
      .. s.critical(trim_end(sparkline(series.s5xx, room, g)))
  end
  local with_date = last - first >= 86400
  local left = with_date and time.format_datetime(first) or time.format_clock(first)
  local right = with_date and time.format_datetime(last) or time.format_clock(last)
  local gap = min(room, n) - #left - #right
  if gap >= 1 then
    out[#out + 1] = " " .. rep(" ", gutter) .. s.muted(left .. rep(" ", gap) .. right)
  end
  out[#out + 1] = ""
end

local function status_bar(ctx, summary, out)
  local s, g = ctx.style, ctx.g
  local counts, legend = {}, {}
  for i, item in ipairs(summary.status.classes) do
    counts[i] = item.count
    if item.count > 0 then
      legend[#legend + 1] = s.colour(CLASS_COLOURS[i])(format("%s %s", item.class,
        util.fmt_pct(item.share)))
    end
  end
  local legend_text = concat(legend, "  ")
  local label = s.accent("STATUS") .. "  "
  local inline = ctx.cw - 8 - visible_width(legend_text) - 2
  local bar_width = inline >= 20 and inline or ctx.cw - 8
  local pieces = {}
  for i, count in ipairs(allocate(counts, bar_width)) do
    if count > 0 then
      pieces[#pieces + 1] = s.colour(CLASS_COLOURS[i])(rep(s.enabled and g.full or g.mono_classes[i],
        count))
    end
  end
  if inline >= 20 then
    out[#out + 1] = " " .. label .. concat(pieces) .. "  " .. legend_text
  else
    out[#out + 1] = " " .. label .. concat(pieces)
    for _, line in ipairs(flow(legend, ctx.cw - 8, 2)) do
      out[#out + 1] = " " .. rep(" ", 8) .. line
    end
  end
  out[#out + 1] = ""
end

-- A ranked table: heading with a caption, then `label  bar  value` rows.
local function ranked_block(ctx, title, caption, rows, width, empty_text)
  local s, g = ctx.style, ctx.g
  local room = max(0, width - #title - 2)
  local block = { s.accent(title) .. "  " .. s.muted(truncate(caption, room, g.ellipsis)) }
  if #rows == 0 then
    block[2] = s.muted(empty_text or "none")
    return block
  end
  local peak, value_width = 0, 0
  for _, row in ipairs(rows) do
    peak, value_width = max(peak, row.value), max(value_width, #row.text)
  end
  local bar_width = width >= 44 and min(10, (width - value_width) // 4) or 0
  local label_width = width - value_width - 1 - (bar_width > 0 and bar_width + 1 or 0)
  for i, row in ipairs(rows) do
    local middle = bar_width > 0 and (" " .. s.bar(bar(row.value, peak, bar_width, g))) or ""
    block[i + 1] = pad_right(fit(ctx, row.label, label_width), label_width) .. middle .. " "
      .. s.bold(pad_left(row.text, value_width))
  end
  return block
end

local function count_rows(list, label_key)
  local rows = {}
  for i, item in ipairs(list) do
    rows[i] = { label = item[label_key], value = item.count, text = util.fmt_int(item.count) }
  end
  return rows
end

local function agents_block(ctx, summary, width)
  local s, g = ctx.style, ctx.g
  local block = { s.accent("AGENTS") .. "  " .. s.muted("by class") }
  local label_width, peak = 8, 0
  local bar_width = max(0, min(14, width - 16))
  for _, item in ipairs(summary.agents.classes) do
    peak = max(peak, item.count)
  end
  for _, item in ipairs(summary.agents.classes) do
    if item.count > 0 then
      local paint = s.colour(AGENT_COLOURS[item.class] or 245)
      block[#block + 1] = paint(pad_right(item.class, label_width)) .. " "
        .. paint(bar(item.count, peak, bar_width, g)) .. " " .. s.bold(pad_left(util.fmt_pct(item.share), 6))
    end
  end
  local families = summary.agents.families
  if #families > 0 then
    block[#block + 1] = ""
    block[#block + 1] = s.muted("top families")
    for i = 1, min(5, #families) do
      local item = families[i]
      local paint = s.colour(AGENT_COLOURS[item.class] or 245)
      block[#block + 1] = paint(pad_right(fit(ctx, item.name, width - 8), width - 7))
        .. s.bold(pad_left(util.fmt_pct(item.share), 6))
    end
  end
  return block
end

local function slowest_block(ctx, summary, width)
  local rows = {}
  for i, item in ipairs(summary.latency.slowest) do
    rows[i] = { label = item.path, value = item.avgMs, text = util.fmt_duration_ms(item.avgMs) }
  end
  return ranked_block(ctx, "SLOWEST", "average time per request", rows, width,
    "no endpoint has enough timed requests")
end

local function spikes_block(ctx, summary, width)
  local s, g = ctx.style, ctx.g
  local block = { s.accent("5XX SPIKES") .. "  " .. s.muted(truncate("outlier minutes", max(0, width - 12), g.ellipsis)) }
  for i = 1, min(5, #summary.errorSpikes) do
    local spike = summary.errorSpikes[i]
    local from = time.format_clock(time.parse_iso(spike.from))
    local to = time.format_clock(time.parse_iso(spike.to))
    block[#block + 1] = s.critical(truncate(format("%s%s%s  %s errors (%s), peak %d/min",
      from, g.arrow, to, util.fmt_int(spike.serverErrors), util.fmt_pct(spike.rate, 0), spike.peak),
      width, g.ellipsis))
  end
  return block
end

-- "from 198.51.100.7, 203.0.113.9 +2 more  .  signatures: union-select 60": who, and what matched.
local function finding_detail(ctx, finding)
  local parts = {}
  local ips = finding.ips
  if #ips > 0 then
    local text = "from " .. concat(ips, ", ", 1, min(3, #ips))
    if #ips > 3 then
      text = text .. format(" +%d more", #ips - 3)
    end
    parts[1] = text
  end
  local labels = finding.evidence[2]
  if labels and (find(labels, "^signatures: ") or find(labels, "^categories: ")) then
    parts[#parts + 1] = labels
  end
  return concat(parts, "  " .. ctx.g.dot .. "  ")
end

-- `limit` caps how many findings are listed (used when the terminal is short).
local function findings(ctx, summary, out, limit)
  local s, g = ctx.style, ctx.g
  local list = summary.findings
  if #list == 0 then
    out[#out + 1] = " " .. s.accent("FINDINGS") .. "  "
      .. s.good(g.ok .. " no suspicious patterns matched")
    out[#out + 1] = ""
    return
  end
  out[#out + 1] = " " .. s.accent("FINDINGS") .. "  " .. s.muted(truncate(format(
    "%d heuristic %s; evidence and limitations in --json", #list,
    #list == 1 and "finding" or "findings"), ctx.cw - 10, g.ellipsis))
  local shown = limit and min(limit, #list) or #list
  for i = 1, shown do
    local finding = list[i]
    local badge = s.badge(finding.severity)
    local count = s.muted(util.fmt_compact(finding.count) .. "x")
    local room = ctx.cw - visible_width(badge) - visible_width(count) - 2
    out[#out + 1] = " " .. badge .. " " .. s.bold(pad_right(fit(ctx, finding.title, room), room))
      .. " " .. count
    local detail = finding_detail(ctx, finding)
    if detail ~= "" then
      local indent = rep(" ", visible_width(badge) + 2)
      out[#out + 1] = indent .. s.muted(fit(ctx, detail, ctx.cw - #indent))
    end
  end
  if shown < #list then
    out[#out + 1] = " " .. s.muted(format("+%d more in --json", #list - shown))
  end
  out[#out + 1] = ""
end

local function footer(ctx, summary, out)
  local s, g = ctx.style, ctx.g
  local lines = summary.meta.lines
  local text = format("parsed %s of %s lines", util.fmt_int(lines.parsed),
    util.fmt_int(lines.total - lines.blank))
  if lines.malformed > 0 then
    text = text .. format("  %s  %s malformed", g.dot, util.fmt_int(lines.malformed))
  end
  if lines.outsideWindow > 0 then
    text = text .. format("  %s  %s outside the time window", g.dot, util.fmt_int(lines.outsideWindow))
  end
  out[#out + 1] = " " .. s.muted(fit(ctx, text, ctx.cw))
  local sample = summary.meta.malformedSamples[1]
  if sample then
    out[#out + 1] = " " .. s.warn(fit(ctx, format("%s line %d: %s: %s", g.warn, sample.line,
      sample.reason, sample.preview), ctx.cw))
  end
end

local function empty_state(ctx, summary, live, out)
  local s = ctx.style
  local lines = summary.meta.lines
  out[#out + 1] = " " .. s.warn("No requests parsed.")
  local hint
  if lines.malformed > 0 then
    hint = "Every line was rejected. Check the format with --format combined|common|json|caddy."
  elseif lines.outsideWindow > 0 then
    hint = "Every request falls outside the time window (--from / --to)."
  elseif lines.total == 0 then
    hint = live and "Waiting for the first request." or "The input is empty."
  end
  for _, line in ipairs(hint and util.wrap(hint, ctx.cw) or {}) do
    out[#out + 1] = " " .. s.muted(line)
  end
  out[#out + 1] = ""
end

-- Lets sections that can list fewer rows (the findings) give up rows until the frame fits, but
-- keep at least `floor` of them. Returns the new total height.
local function shrink_sections(sections, total, max_lines, floor)
  for _, section in ipairs(sections) do
    if section.shrink and total > max_lines then
      local lines = section.shrink(#section.lines - (total - max_lines), floor)
      total, section.lines = total - #section.lines + #lines, lines
    end
  end
  return total
end

-- Joins the sections into the final text. When `max_lines` is set and the frame is taller, the
-- least important optional sections (priority below 90) go first; before the main lists are
-- touched the findings are cut down to three; then the lists, traffic and status follow, the
-- findings shrink further, and as a last resort the tail is cut.
local function finish(sections, max_lines)
  local total = 0
  for _, section in ipairs(sections) do
    total = total + #section.lines
  end
  if max_lines and total > max_lines then
    local optional = {}
    for _, section in ipairs(sections) do
      if section.priority < 90 then
        optional[#optional + 1] = section
      end
    end
    sort(optional, function(a, b)
      if a.priority ~= b.priority then
        return a.priority < b.priority
      end
      return a.index > b.index
    end)
    local trimmed_findings = false
    for _, section in ipairs(optional) do
      if section.priority >= 60 and not trimmed_findings then
        total, trimmed_findings = shrink_sections(sections, total, max_lines, 3), true
      end
      if total > max_lines then
        total, section.lines = total - #section.lines, {}
      end
    end
    shrink_sections(sections, total, max_lines, 0)
  end
  local out = {}
  for _, section in ipairs(sections) do
    for _, line in ipairs(section.lines) do
      out[#out + 1] = trim_end(line)
    end
  end
  for i = #out, (max_lines or #out) + 1, -1 do
    out[i] = nil
  end
  return concat(out, "\n") .. "\n"
end

--- Renders the dashboard.
-- @param summary table a `loglens.summary/v1` summary
-- @param opts table|nil `{ width = 100, color = true, ascii = false, frame = 0, live = { status =
--   "tailing"|"rotated"|"waiting", new_lines = 0 }, max_lines = nil }`; `live` adds the animated
--   LIVE header whose pulse and spinner are driven by `frame`; `max_lines` fits the frame into a
--   terminal of that height by leaving out the least important sections
-- @return string lines separated by "\n", ending with a newline, no line wider than `width`
function M.render(summary, opts)
  opts = opts or {}
  local width = max(40, min(240, floor(opts.width or 100)))
  local ctx = {
    width = width,
    cw = width - 2,
    style = make_style(opts.color ~= false),
    g = opts.ascii and GLYPHS.ascii or GLYPHS.unicode,
  }
  local max_lines = opts.max_lines and max(8, floor(opts.max_lines)) or nil
  local sections = {}
  -- Sections are built in display order; `priority` decides what a short terminal drops first.
  local function add(priority, build)
    local section = { priority = priority, index = #sections + 1, lines = {} }
    build(section.lines)
    sections[#sections + 1] = section
    return section
  end

  add(100, function(out)
    header(ctx, summary, opts, out)
  end)
  if summary.totals.requests == 0 then
    add(100, function(out)
      empty_state(ctx, summary, opts.live, out)
    end)
    add(100, function(out)
      footer(ctx, summary, out)
    end)
    return finish(sections, max_lines)
  end
  add(90, function(out)
    kpis(ctx, summary, out)
  end)
  add(80, function(out)
    traffic(ctx, summary, out)
  end)
  add(85, function(out)
    status_bar(ctx, summary, out)
  end)

  local two_columns = ctx.cw >= 94
  local gap = 3
  local left_width = two_columns and (ctx.cw - gap) // 2 or ctx.cw
  local right_width = two_columns and (ctx.cw - left_width - gap) or ctx.cw
  local function place(priority, left, right)
    add(priority, function(out)
      if two_columns and right then
        for _, line in ipairs(columns({ left, right }, { left_width, right_width }, gap)) do
          out[#out + 1] = " " .. line
        end
      else
        for _, line in ipairs(left) do
          out[#out + 1] = " " .. line
        end
        if right then
          out[#out + 1] = ""
          for _, line in ipairs(right) do
            out[#out + 1] = " " .. line
          end
        end
      end
      out[#out + 1] = ""
    end)
  end

  place(60, ranked_block(ctx, "TOP PATHS", "requests", count_rows(summary.paths, "path"), left_width),
    ranked_block(ctx, "TOP CLIENTS", "requests", count_rows(summary.clients, "ip"), right_width))
  place(30, ranked_block(ctx, "REFERRERS", "requests", count_rows(summary.referrers, "host"),
    left_width, "no referrers in this log"), agents_block(ctx, summary, right_width))
  local not_found, server_errors = summary.errorPaths.notFound, summary.errorPaths.serverErrors
  if #not_found > 0 or #server_errors > 0 then
    place(20, ranked_block(ctx, "NOT FOUND", "404 responses", count_rows(not_found, "path"),
      left_width), ranked_block(ctx, "SERVER ERRORS", "5xx responses",
      count_rows(server_errors, "path"), right_width))
  end
  local has_spikes = #summary.errorSpikes > 0
  if summary.latency then
    place(50, slowest_block(ctx, summary, left_width),
      has_spikes and spikes_block(ctx, summary, right_width) or nil)
  elseif has_spikes then
    place(50, spikes_block(ctx, summary, ctx.cw))
  end
  local list = add(95, function(out)
    findings(ctx, summary, out)
  end)
  -- The rows the findings need for `budget` lines, listing at least `floor` of them.
  list.shrink = function(budget, floor)
    floor = min(floor, #summary.findings)
    for limit = #summary.findings - 1, floor, -1 do
      local lines = {}
      findings(ctx, summary, lines, limit)
      if #lines <= budget then
        return lines
      end
    end
    local lines = {}
    findings(ctx, summary, lines, floor)
    return lines
  end
  add(100, function(out)
    footer(ctx, summary, out)
  end)
  return finish(sections, max_lines)
end

--- Sparkline helper, exposed for tests and other renderers.
-- @param values number[]
-- @param width number
-- @param ascii boolean|nil
-- @return string
function M.sparkline(values, width, ascii)
  return sparkline(values, width, ascii and GLYPHS.ascii or GLYPHS.unicode)
end

--- Horizontal bar helper, exposed for tests and other renderers.
-- @param value number
-- @param peak number value that fills the whole bar
-- @param width number
-- @param ascii boolean|nil
-- @return string exactly `width` columns wide
function M.bar(value, peak, width, ascii)
  return bar(value, peak, width, ascii and GLYPHS.ascii or GLYPHS.unicode)
end

M.allocate = allocate

return M
