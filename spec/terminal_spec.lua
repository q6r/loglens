local t = require("spec.support")
local analyzer = require("loglens.analyzer")
local loggen = require("tools.loggen")
local terminal = require("loglens.render.terminal")
local util = require("loglens.util")

---------------------------------------------------------------------------------------------
-- A small, hand-shaped log: arithmetic patterns (no random numbers), a probe, a SQL injection
-- by sqlmap and a burst of 503s, so every dashboard section has content.
---------------------------------------------------------------------------------------------

local CLIENTS = { "203.0.113.10", "203.0.113.11", "203.0.113.12", "198.51.100.7", "2001:db8::5" }
local PAGES = { "/", "/pricing", "/blog/hello", "/static/app.js", "/api/items?page=2", "/missing" }
local STATUSES = { 200, 200, 200, 304, 200, 200, 200, 500, 200, 301 }
local REFERRERS = { "-", "https://www.google.com/", "https://example.com/", "-" }
local AGENTS = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "curl/8.4.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

local function golden_lines()
  local lines = {}
  local function add(ip, minute, second, method, target, status, bytes, referer, ua, rt)
    lines[#lines + 1] = string.format(
      '%s - - [10/Nov/2026:14:%02d:%02d +0000] "%s %s HTTP/1.1" %d %d "%s" "%s" %.3f', ip, minute,
      second, method, target, status, bytes, referer, ua, rt)
  end
  for i = 0, 71 do
    local target = PAGES[i % 6 + 1]
    local status = target == "/missing" and 404 or STATUSES[i % 10 + 1]
    local rt = 0.010 + (i % 9) * 0.03 + (target:find("^/api") and 1.2 or 0)
    add(CLIENTS[i % 5 + 1], i // 6, (i % 6) * 10 + 3, "GET", target, status, 500 + (i * 37) % 3000,
      REFERRERS[i % 4 + 1], AGENTS[i % 5 + 1], rt)
  end
  for i, path in ipairs({ "/.env", "/wp-login.php", "/phpmyadmin/" }) do
    add("192.0.2.99", 5, 40 + i, "GET", path, 404, 150, "-", "-", 0.004)
  end
  for i = 1, 2 do
    add("192.0.2.98", 6, 20 + i, "GET", "/api/items?id=1' OR '1'='1", 200, 900, "-",
      "sqlmap/1.7.11#stable (https://sqlmap.org)", 0.250)
  end
  for i = 1, 8 do
    add(CLIENTS[i % 5 + 1], 9, 5 + i * 5, "GET", "/api/items", 503, 300, "-", AGENTS[1], 1.5)
  end
  return lines
end

local function golden_summary()
  return analyzer.analyze_lines(golden_lines(), { sources = { "golden.log" }, now = 1794312189 })
end

local function without_sgr(text)
  return (text:gsub("\27%[[%d;]*m", ""))
end

-- Colour only decorates. The two deliberate differences between the coloured and the monochrome
-- frame are neutralised here: the status bar fill (solid blocks in colour, one texture per class in
-- mono so the classes stay apart) and the severity badge (a padded pill in colour, `[MED ]` in mono).
local function undecorated(text)
  local lines = {}
  for i, line in ipairs(t.lines_of(text)) do
    line = line:gsub("^( STATUS  )(%S+)", function(lead, fill)
      return lead .. string.rep("#", utf8.len(fill))
    end)
    lines[i] = (line:gsub("%[(%u+ ?)%]", " %1 "))
  end
  return table.concat(lines, "\n")
end

local function widest(text)
  local widest_line = 0
  for _, l in ipairs(t.lines_of(text)) do
    widest_line = math.max(widest_line, util.visible_width(l))
  end
  return widest_line
end

---------------------------------------------------------------------------------------------

t.describe("terminal primitives", function()
  t.it("draws sparklines scaled to the peak with blanks for zero", function()
    t.eq(terminal.sparkline({ 0, 1, 2, 4, 8 }, 10), " \u{2581}\u{2582}\u{2584}\u{2588}")
    t.eq(terminal.sparkline({ 5, 5, 5 }, 10), "\u{2588}\u{2588}\u{2588}")
    t.eq(terminal.sparkline({}, 10), "")
    t.eq(terminal.sparkline({ 0, 0, 0 }, 10), "   ")
    t.eq(terminal.sparkline({ 0, 1, 2, 4, 8 }, 10, true), " .:=@")
  end)

  t.it("resamples long series by maximum", function()
    local values = {}
    for i = 1, 16 do
      values[i] = i
    end
    t.eq(terminal.sparkline(values, 4), "\u{2582}\u{2584}\u{2586}\u{2588}")
    t.eq(#terminal.sparkline(values, 7), 7 * #"\u{2588}")
    t.eq(terminal.sparkline({ 1, 9, 1, 1 }, 2), "\u{2588}\u{2581}", "a spike survives downsampling")
    t.eq(terminal.sparkline({ 1, 1, 1, 9 }, 2), "\u{2581}\u{2588}", "and keeps its side of the series")
  end)

  t.it("clips extreme outliers on long series instead of flattening the rest", function()
    local values = {}
    for i = 1, 100 do
      values[i] = i
    end
    values[100] = 5000
    local line = terminal.sparkline(values, 100)
    t.eq(line:sub(-3), "\u{2588}")
    local chars = {}
    for _, cp in utf8.codes(line) do
      chars[#chars + 1] = utf8.char(cp)
    end
    t.eq(chars[100], "\u{2588}")
    t.eq(chars[49], "\u{2584}", "half of the clipped scale")
    t.eq(chars[1], "\u{2581}")
  end)

  t.it("draws bars of an exact width with eighth-block resolution", function()
    t.eq(terminal.bar(5, 10, 10), "\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}     ")
    t.eq(terminal.bar(1, 10, 10), "\u{2588}         ")
    t.eq(terminal.bar(1, 100, 10), "\u{258F}         ")
    t.eq(terminal.bar(3, 100, 10), "\u{258E}         ".. "", "3% rounds to 2/8 of a cell")
    t.eq(terminal.bar(10, 10, 3), "\u{2588}\u{2588}\u{2588}")
    t.eq(terminal.bar(0, 10, 5), "     ")
    t.eq(terminal.bar(5, 10, 10, true), "#####     ")
    t.eq(terminal.bar(1, 1000, 10, true), "#         ")
    for value = 0, 100 do
      t.eq(util.display_width(terminal.bar(value, 100, 12)), 12)
    end
  end)

  t.it("splits a width between counts without losing cells", function()
    t.eq(terminal.allocate({ 50, 30, 15, 5 }, 20), { 10, 6, 3, 1 })
    t.eq(terminal.allocate({ 1, 0, 0, 999 }, 10), { 1, 0, 0, 9 })
    t.eq(terminal.allocate({ 1000, 1, 1 }, 10), { 8, 1, 1 })
    t.eq(terminal.allocate({ 0, 0 }, 10), { 0, 0 })
    for width = 1, 60 do
      local cells = terminal.allocate({ 871, 53, 36, 36, 4 }, width)
      local sum = 0
      for _, n in ipairs(cells) do
        sum = sum + n
      end
      t.eq(sum, width)
    end
  end)
end)

t.describe("terminal frames (golden)", function()
  t.it("renders the 80 column unicode dashboard", function()
    t.golden("dashboard-80.txt", terminal.render(golden_summary(), { width = 80, color = false }))
  end)

  t.it("renders the 60 column ASCII dashboard", function()
    t.golden("dashboard-60-ascii.txt", terminal.render(golden_summary(), { width = 60, color = false, ascii = true }))
  end)

  t.it("renders the 100 column two-column dashboard", function()
    t.golden("dashboard-100.txt", terminal.render(golden_summary(), { width = 100, color = false }))
  end)

  t.it("renders the ANSI colour dashboard", function()
    t.golden("dashboard-80-ansi.txt", terminal.render(golden_summary(), { width = 80 }))
  end)

  t.it("renders the live header frames", function()
    local summary = golden_summary()
    local headers = {}
    for frame = 0, 3 do
      headers[#headers + 1] = t.lines_of(terminal.render(summary,
        { width = 100, color = false, frame = frame, live = { status = "tailing", new_lines = 37 } }))[1]
    end
    t.eq(headers, {
      " loglens  \u{25CF} LIVE \u{280B} +37 new  golden.log \u{00B7} combined \u{00B7} 2026-11-10 14:00 \u{2192} 14:11 UTC (12m)",
      " loglens  \u{25CB} LIVE \u{2819} +37 new  golden.log \u{00B7} combined \u{00B7} 2026-11-10 14:00 \u{2192} 14:11 UTC (12m)",
      " loglens  \u{25CF} LIVE \u{2839} +37 new  golden.log \u{00B7} combined \u{00B7} 2026-11-10 14:00 \u{2192} 14:11 UTC (12m)",
      " loglens  \u{25CB} LIVE \u{2838} +37 new  golden.log \u{00B7} combined \u{00B7} 2026-11-10 14:00 \u{2192} 14:11 UTC (12m)",
    })
    local ascii = t.lines_of(terminal.render(summary, { width = 100, color = false, ascii = true, frame = 5,
      live = { status = "tailing", new_lines = 0 } }))[1]
    t.eq(ascii, " loglens  o LIVE / +0 new  golden.log - combined - 2026-11-10 14:00 -> 14:11 UTC (12m)")
    t.contains(t.lines_of(terminal.render(summary, { width = 100, color = false,
      live = { status = "rotated" } }))[1], "log rotated, following the new file")
    t.contains(t.lines_of(terminal.render(summary, { width = 100, color = false,
      live = { status = "waiting" } }))[1], "waiting for the file")
  end)
end)

t.describe("terminal content", function()
  local summary = golden_summary()
  local plain = terminal.render(summary, { width = 100, color = false })

  t.it("shows every section for a rich log", function()
    for _, heading in ipairs({ "REQUESTS", "BANDWIDTH", "VISITORS", "AVG RATE", "5XX RATE", "LATENCY P99",
      "TRAFFIC", "STATUS", "TOP PATHS", "TOP CLIENTS", "REFERRERS", "AGENTS", "NOT FOUND",
      "SERVER ERRORS", "SLOWEST", "5XX SPIKES", "FINDINGS" }) do
      t.contains(plain, heading)
    end
    t.contains(plain, "[MED ] SQL injection signatures in URLs")
    t.contains(plain, "[LOW ] Probing for sensitive or admin paths")
    t.contains(plain, "from 192.0.2.98")
  end)

  t.it("ends with a newline and has no trailing spaces", function()
    t.eq(plain:sub(-1), "\n")
    for _, l in ipairs(t.lines_of(plain)) do
      t.is_nil(l:find(" $"), "trailing space in: " .. l)
    end
  end)

  t.it("emits no escape sequences without colour and only SGR sequences with colour", function()
    t.not_contains(plain, "\27")
    local coloured = terminal.render(summary, { width = 100 })
    t.contains(coloured, "\27[")
    t.not_contains(without_sgr(coloured), "\27")
    t.eq(undecorated(without_sgr(coloured)), undecorated(plain))
  end)

  t.it("shows severity badges as reverse-video labels in colour and brackets in mono", function()
    -- every badge is padded to the same width so the finding titles line up in both modes
    t.contains(terminal.render(summary, { width = 100 }), "\27[1;38;5;16;48;5;221m MED  \27[0m")
    t.contains(terminal.render(summary, { width = 100 }), "\27[1;38;5;16;48;5;110m LOW  \27[0m")
    t.contains(plain, "[MED ]")
  end)

  t.it("does not modify the summary and is deterministic", function()
    local before = require("loglens.json").encode(summary)
    local first = terminal.render(summary, { width = 90 })
    t.eq(terminal.render(summary, { width = 90 }), first)
    t.eq(require("loglens.json").encode(summary), before)
  end)

  t.it("uses two columns when wide and stacks blocks when narrow", function()
    t.matches(plain, "TOP PATHS +requests +TOP CLIENTS")
    local narrow = terminal.render(summary, { width = 70, color = false })
    t.not_contains(narrow, "TOP PATHS  requests   TOP CLIENTS")
    t.matches(narrow, "TOP PATHS.-\n.-TOP CLIENTS")
    local first_kpi_rows = t.lines_of(narrow)
    t.contains(table.concat(first_kpi_rows, "\n", 1, 12), "AVG RATE")
  end)

  t.it("marks an estimated visitor count and shows n/a without request times", function()
    local copy = require("loglens.json").decode(require("loglens.summary").encode(summary))
    copy.totals.uniqueIpsExact = false
    copy.latency = nil
    local out = terminal.render(copy, { width = 100, color = false })
    t.contains(out, "\u{2248} 7", "five clients and two attackers")
    t.contains(out, "n/a")
    t.contains(out, "no request_time")
    t.not_contains(out, "SLOWEST")
    t.contains(terminal.render(copy, { width = 100, color = false, ascii = true }), "~7")
    t.not_contains(plain, "\u{2248}", "an exact count carries no marker")
  end)

  t.it("shows the empty and rejected-input states", function()
    local empty = analyzer.analyze_lines({}, { format = "combined" })
    local out = terminal.render(empty, { width = 80, color = false })
    t.contains(out, "No requests parsed.")
    t.contains(out, "The input is empty.")
    local junk = analyzer.analyze_lines({ "hello", "world" })
    local junk_out = terminal.render(junk, { width = 80, color = false })
    t.contains(junk_out, "Every line was rejected")
    t.contains(junk_out, "line 1: missing [timestamp]: hello")
    t.contains(junk_out, "2 malformed")
  end)

  t.it("uses the hourly series and dates for multi-day logs", function()
    local lines = {}
    for day = 1, 4 do
      for hour = 0, 23, 3 do
        lines[#lines + 1] = string.format('203.0.113.1 - - [%02d/Nov/2026:%02d:10:00 +0000] "GET / HTTP/1.1" 200 10', day, hour)
      end
    end
    local out = terminal.render(analyzer.analyze_lines(lines), { width = 100, color = false })
    t.contains(out, "requests per hour")
    t.contains(out, "2026-11-01 00:00")
    t.contains(out, "2026-11-04 21:00")
    t.contains(out, "(3d 21h)" == nil and "" or "UTC (4d)")
  end)

  t.it("reports a healthy log without findings", function()
    local lines = {}
    for i = 1, 30 do
      lines[i] = string.format('203.0.113.%d - - [10/Nov/2026:14:%02d:00 +0000] "GET /p%d HTTP/1.1" 200 100 "-" "Mozilla/5.0 Chrome/120"', i % 4 + 1, i % 20, i % 3)
    end
    local out = terminal.render(analyzer.analyze_lines(lines), { width = 100, color = false })
    t.contains(out, "FINDINGS  \u{2713} no suspicious patterns matched")
    t.not_contains(out, "SERVER ERRORS")
    t.not_contains(out, "5XX SPIKES")
    t.contains(terminal.render(analyzer.analyze_lines(lines), { width = 100, color = false, ascii = true }),
      "FINDINGS  ok no suspicious patterns matched")
  end)
end)

t.describe("terminal layout invariants", function()
  local big = analyzer.analyze_lines(loggen.lines({ seed = 4, count = 700 }), { sources = { "a.log", "b.log" } })

  t.it("never exceeds the requested width in any mode", function()
    for _, width in ipairs({ 40, 41, 52, 59, 60, 79, 80, 87, 88, 93, 94, 95, 100, 120, 132, 200, 240 }) do
      for _, mode in ipairs({
        { color = false },
        { color = true },
        { color = false, ascii = true },
        { color = true, ascii = true, frame = 2, live = { new_lines = 5 } },
      }) do
        local opts = { width = width, color = mode.color, ascii = mode.ascii, frame = mode.frame, live = mode.live }
        local out = terminal.render(big, opts)
        t.ok(widest(out) <= width, string.format("width %d, ascii=%s color=%s: widest line is %d", width,
          tostring(mode.ascii), tostring(mode.color), widest(out)))
      end
    end
  end)

  t.it("clamps absurd widths and accepts fractional ones", function()
    t.ok(widest(terminal.render(big, { width = 5, color = false })) <= 40)
    t.ok(widest(terminal.render(big, { width = 5000, color = false })) <= 240)
    t.eq(terminal.render(big, { width = 80.9, color = false }), terminal.render(big, { width = 80, color = false }))
    t.eq(terminal.render(big, { color = false }), terminal.render(big, { width = 100, color = false }))
  end)

  t.it("fits a short terminal by leaving out the least important sections first", function()
    local function height(text)
      return #t.lines_of(text)
    end
    local order = { "REQUESTS", "STATUS", "TRAFFIC", "FINDINGS", "TOP PATHS", "SLOWEST", "AGENTS", "NOT FOUND" }
    local previous
    for rows = 8, 90, 2 do
      local out = terminal.render(big, { width = 100, color = false, max_lines = rows })
      t.ok(height(out) <= rows, string.format("%d lines for a budget of %d", height(out), rows))
      local present = {}
      for _, heading in ipairs(order) do
        present[heading] = out:find(heading, 1, true) ~= nil
      end
      if previous then
        for _, heading in ipairs(order) do
          t.ok(present[heading] or not previous[heading],
            string.format("%s was shown with %d lines and vanished with %d", heading, rows - 2, rows))
        end
      end
      previous = present
    end
    local medium = terminal.render(big, { width = 100, color = false, max_lines = 43 })
    t.contains(medium, "TOP PATHS", "the main lists stay while findings give up rows")
    t.matches(medium, "%+%d+ more in %-%-json")
    t.not_contains(medium, "NOT FOUND")
    t.contains(terminal.render(big, { width = 100, color = false, max_lines = 28 }), "FINDINGS")
    t.eq(terminal.render(big, { width = 100, color = false, max_lines = 500 }), terminal.render(big, { width = 100, color = false }),
      "a tall terminal changes nothing")
  end)

  t.it("keeps the live header and the empty states inside a narrow terminal", function()
    local summary = golden_summary()
    for _, status in ipairs({ "tailing", "rotated", "waiting" }) do
      for _, ascii in ipairs({ false, true }) do
        local out = terminal.render(summary, { width = 40, color = true, ascii = ascii, frame = 3,
          live = { status = status, new_lines = 1234567 } })
        t.ok(widest(out) <= 40, string.format("live %s, ascii=%s: widest line is %d", status,
          tostring(ascii), widest(out)))
      end
    end
    for _, empty in ipairs({ analyzer.analyze_lines({}, { format = "combined" }),
      analyzer.analyze_lines({ "hello", "world" }) }) do
      t.ok(widest(terminal.render(empty, { width = 40, color = false })) <= 40)
    end
  end)

  t.it("emits only ASCII characters in ascii mode", function()
    local out = terminal.render(golden_summary(), { width = 90, color = true, ascii = true,
      live = { new_lines = 3 } })
    t.is_nil(out:find("[\128-\255]"), "a non-ASCII byte leaked into the ASCII frame")
  end)

  t.it("summarises several sources by count", function()
    t.contains(terminal.render(big, { width = 100, color = false }), "2 files")
  end)
end)

t.describe("terminal output safety", function()
  local lines = {
    '203.0.113.5 - - [10/Nov/2026:14:00:00 +0000] "GET /\\x1b[31mred\\x1b[0m<script>alert(1)</script> HTTP/1.1" 404 10 "https://\\x1b]0;owned\\x07.example/" "\\x1b[2J<img src=x onerror=alert(1)>${jndi:ldap://x/a}"',
    '203.0.113.6 - - [10/Nov/2026:14:00:01 +0000] "GET /\xe2\x80\xaegpj.exe HTTP/1.1" 200 10 "-" "\xff\xfe binary \xc3"',
    '203.0.113.7 - - [10/Nov/2026:14:00:02 +0000] "GET /' .. string.rep("long/", 400) .. ' HTTP/1.1" 200 10 "-" "-"',
  }
  local summary = analyzer.analyze_lines(lines, { sources = { "/tmp/\27[31mevil\27[0m.log" } })

  t.it("never lets log text inject terminal sequences or live markup", function()
    for _, opts in ipairs({ { color = false }, { color = true }, { color = false, ascii = true } }) do
      opts.width = 100
      local out = terminal.render(summary, opts)
      local text = without_sgr(out)
      t.not_contains(text, "\27", "no raw escape characters")
      t.not_contains(text, "\r")
      t.not_contains(text, "\7")
      t.not_contains(text, "\0")
      t.not_contains(text, "<script")
      t.not_contains(text, "<img")
      t.not_contains(text, "${")
      t.not_contains(text, "\xe2\x80\xae")
      t.not_contains(text, "\xff")
      t.ok(utf8.len(text), "output must be valid UTF-8")
      t.ok(widest(out) <= 100)
      t.contains(text, "%3Cscript%3E")
      t.contains(text, "\\x1B")
      t.contains(text, "\\u202E")
    end
  end)
end)
