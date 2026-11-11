local t = require("spec.support")
local analyzer = require("loglens.analyzer")
local json = require("loglens.json")
local loggen = require("tools.loggen")
local summary_format = require("loglens.summary")
local time = require("loglens.time")

local STAMP = "[10/Nov/2026:14:03:09 +0200]"

local function line(ip, path, status, extra)
  return string.format('%s - - %s "GET %s HTTP/1.1" %d 100%s', ip, STAMP, path, status, extra or "")
end

local function valid(summary)
  local ok, errors = summary_format.validate(summary)
  t.ok(ok, "summary must validate: " .. t.inspect(errors))
end

t.describe("analyzer basics", function()
  t.it("analyses lines and reports metadata", function()
    local a = analyzer.new({ sources = { "access.log" }, now = 1794312189 })
    a:feed(line("203.0.113.1", "/a", 200, ' "-" "curl/8"'))
    a:feed(line("203.0.113.2", "/b", 404, ' "-" "curl/8"'))
    local s = a:summary()
    valid(s)
    t.eq(s.schema, "loglens.summary/v1")
    t.eq(s.meta.tool, "loglens")
    t.eq(s.meta.version, require("loglens.version"))
    t.eq(s.meta.generatedAt, "2026-11-10T12:03:09Z")
    t.eq(s.meta.sources, { "access.log" })
    t.eq(s.meta.format, "combined")
    t.is_true(s.meta.autoDetected)
    t.eq(s.meta.lines, { total = 2, parsed = 2, malformed = 0, blank = 0, outsideWindow = 0 })
    t.eq(s.totals.requests, 2)
    t.eq(s.status.classes[4].count, 1)
  end)

  t.it("omits generatedAt without a clock and accepts a clock function", function()
    local a = analyzer.new()
    t.is_nil(a:summary().meta.generatedAt)
    local b = analyzer.new({ now = function()
      return 0 + 1794312189
    end })
    t.eq(b:summary().meta.generatedAt, "2026-11-10T12:03:09Z")
  end)

  t.it("summarises empty input", function()
    local s = analyzer.new():summary()
    valid(s)
    t.eq(s.meta.format, "unknown")
    t.is_false(s.meta.autoDetected)
    t.eq(s.totals.requests, 0)
    t.eq(s.findings, {})
    local explicit = analyzer.new({ format = "json" }):summary()
    t.eq(explicit.meta.format, "json")
    valid(explicit)
  end)

  t.it("skips blank lines, strips CR and a BOM", function()
    local a = analyzer.new()
    a:feed("\239\187\191" .. line("203.0.113.1", "/a", 200) .. "\r")
    a:feed("")
    a:feed("   \t ")
    a:feed(line("203.0.113.1", "/b", 200) .. "\r")
    local s = a:summary()
    t.eq(s.meta.lines, { total = 4, parsed = 2, malformed = 0, blank = 2, outsideWindow = 0 })
  end)

  t.it("counts and samples malformed lines with their line numbers", function()
    local a = analyzer.new({ malformed_samples = 3 })
    a:feed(line("203.0.113.1", "/a", 200))
    a:feed("")
    a:feed("this is not a log line")
    a:feed(line("203.0.113.1", "/b", 99))
    a:feed('203.0.113.1 - - [bad date] "GET / HTTP/1.1" 200 1')
    a:feed("\27[31m<script>alert(1)</script>\0")
    a:feed("one more")
    local s = a:summary()
    t.eq(s.meta.lines.malformed, 5)
    t.eq(s.meta.lines.parsed, 1)
    t.eq(#s.meta.malformedSamples, 3)
    t.eq(s.meta.malformedSamples[1].line, 3)
    t.eq(s.meta.malformedSamples[1].reason, "missing [timestamp]")
    t.eq(s.meta.malformedSamples[1].preview, "this is not a log line")
    t.eq(s.meta.malformedSamples[2], { line = 4, reason = "bad status code",
      preview = "203.0.113.1 - - [10/Nov/2026:14:03:09 +0200] %22GET /b HTTP/1.1%22 99 100" })
    valid(s)
  end)

  t.it("defangs malformed previews", function()
    local a = analyzer.new({ format = "combined" })
    a:feed("\27[31m<script>alert('x')</script>\xff\0 [")
    local preview = a:summary().meta.malformedSamples[1].preview
    t.not_contains(preview, "\27")
    t.not_contains(preview, "<")
    t.not_contains(preview, "\0")
    t.contains(preview, "%3Cscript%3E")
  end)

  t.it("rejects oversized lines without parsing them", function()
    local a = analyzer.new({ max_line_bytes = 200 })
    a:feed(line("203.0.113.1", "/" .. string.rep("a", 300), 200))
    a:feed(line("203.0.113.1", "/ok", 200))
    local s = a:summary()
    t.eq(s.meta.lines.malformed, 1)
    t.contains(s.meta.malformedSamples[1].reason, "line too long")
    t.lt(#s.meta.malformedSamples[1].preview, 170)
    t.eq(s.totals.requests, 1)
  end)

  t.it("turns parser crashes into malformed lines instead of failing", function()
    local a = analyzer.new({ format = "combined" })
    a.parse = function()
      error("boom")
    end
    a:feed(line("203.0.113.1", "/a", 200))
    local s = a:summary()
    t.eq(s.meta.lines.malformed, 1)
    t.contains(s.meta.malformedSamples[1].reason, "parser error")
    t.contains(s.meta.malformedSamples[1].reason, "boom")
  end)
end)

t.describe("analyzer format handling", function()
  local LINES = {
    line("203.0.113.1", "/a", 200, ' "https://example.com/" "Mozilla/5.0 Chrome/120"'),
    line("203.0.113.2", "/b?x=1", 404, ' "-" "curl/8"'),
  }

  t.it("honours an explicit format and counts mismatches as malformed", function()
    local s = analyzer.analyze_lines(LINES, { format = "json" })
    t.eq(s.meta.format, "json")
    t.is_false(s.meta.autoDetected)
    t.eq(s.meta.lines.malformed, 2)
    t.eq(s.totals.requests, 0)
    t.contains(s.meta.malformedSamples[1].reason, "invalid JSON")
    local common = analyzer.analyze_lines(LINES, { format = "common" })
    t.eq(common.totals.requests, 2)
    t.eq(#common.referrers, 0, "common ignores referers")
  end)

  t.it("rejects unknown formats and bad options", function()
    t.raises(function()
      analyzer.new({ format = "apache" })
    end, "unknown format 'apache'")
    t.raises(function()
      analyzer.new({ from = "yesterday" })
    end, "invalid 'from' value")
    t.raises(function()
      analyzer.new({ to = "soon" })
    end, "invalid 'to' value")
    t.raises(function()
      analyzer.new({ from = "2026-11-11T00:00:00Z", to = "2026-11-10T00:00:00Z" })
    end, "'from' must not be later than 'to'")
  end)

  t.it("falls back to combined when detection finds nothing", function()
    local s = analyzer.analyze_lines({ "hello", "world" })
    t.eq(s.meta.format, "combined")
    t.is_false(s.meta.autoDetected)
    t.eq(s.meta.lines.malformed, 2)
  end)

  t.it("detects after the buffer fills and replays buffered lines in order", function()
    local lines = {}
    for i = 1, 30 do
      lines[i] = line("203.0.113." .. i, "/p" .. i, 200)
    end
    lines[3] = "garbage three"
    local s = analyzer.analyze_lines(lines, { detect_lines = 5 })
    t.eq(s.meta.lines.parsed, 29)
    t.eq(s.meta.malformedSamples[1].line, 3)
  end)

  t.it("can be summarised before detection completes and keeps going", function()
    local a = analyzer.new({ detect_lines = 10 })
    local extra = ' "-" "curl/8"'
    a:feed(line("203.0.113.1", "/a", 200, extra))
    a:feed(line("203.0.113.2", "/b", 200, extra))
    t.eq(a:summary().totals.requests, 2)
    for i = 3, 12 do
      a:feed(line("203.0.113." .. i, "/c", 200, extra))
    end
    local s = a:summary()
    t.eq(s.totals.requests, 12)
    t.eq(s.meta.format, "combined")
    valid(s)

    local plain = analyzer.new()
    plain:feed(line("203.0.113.1", "/a", 200))
    t.eq(plain:summary().meta.format, "common", "the format is decided from what has been seen")
  end)

  t.it("produces the same figures from the same traffic in every format", function()
    local base = { seed = 11, count = 400, attacks = false, timing = true }
    local results = {}
    for _, format in ipairs({ "combined", "json", "caddy" }) do
      local opts = {}
      for key, value in pairs(base) do
        opts[key] = value
      end
      opts.format = format
      local lines = loggen.lines(opts)
      local s = analyzer.analyze_lines(lines)
      t.eq(s.meta.format, format)
      t.eq(s.meta.lines.malformed, 0, format)
      valid(s)
      results[format] = s
    end
    local reference = results.combined
    for _, format in ipairs({ "json", "caddy" }) do
      local other = results[format]
      t.eq(other.totals.requests, reference.totals.requests, format)
      t.eq(other.totals.bytes, reference.totals.bytes, format)
      t.eq(other.status, reference.status, format)
      t.eq(other.paths, reference.paths, format)
      t.eq(other.clients, reference.clients, format)
      t.eq(other.agents.classes, reference.agents.classes, format)
      t.eq(other.timeline.hour, reference.timeline.hour, format)
    end
    t.eq(results.common, nil)
    local common = analyzer.analyze_lines(loggen.lines({ seed = 11, count = 400, attacks = false, format = "common" }))
    t.eq(common.meta.format, "common")
    t.eq(common.totals.requests, reference.totals.requests)
    t.eq(common.totals.bytes, reference.totals.bytes)
  end)
end)

t.describe("analyzer time window", function()
  local function stamped(hour)
    return string.format('203.0.113.1 - - [10/Nov/2026:%02d:00:00 +0000] "GET /h%d HTTP/1.1" 200 10', hour, hour)
  end
  local LINES = {}
  for hour = 8, 17 do
    LINES[#LINES + 1] = stamped(hour)
  end

  t.it("keeps only requests inside the inclusive window", function()
    local s = analyzer.analyze_lines(LINES, { from = "2026-11-10T10:00:00Z", to = "2026-11-10T12:00:00Z" })
    t.eq(s.totals.requests, 3)
    t.eq(s.meta.lines.parsed, 10)
    t.eq(s.meta.lines.outsideWindow, 7)
    t.eq(s.meta.window, { from = "2026-11-10T10:00:00Z", to = "2026-11-10T12:00:00Z" })
    t.eq(s.totals.firstSeen, "2026-11-10T10:00:00Z")
    t.eq(s.totals.lastSeen, "2026-11-10T12:00:00Z")
    valid(s)
  end)

  t.it("accepts epoch numbers and open-ended windows", function()
    local from = time.parse_iso("2026-11-10T16:00:00Z")
    local s = analyzer.analyze_lines(LINES, { from = from })
    t.eq(s.totals.requests, 2)
    t.eq(s.meta.window, { from = "2026-11-10T16:00:00Z" })
    local until_only = analyzer.analyze_lines(LINES, { to = time.parse_iso("2026-11-10T08:30:00Z") })
    t.eq(until_only.totals.requests, 1)
    t.eq(until_only.meta.window, { to = "2026-11-10T08:30:00Z" })
  end)

  t.it("encodes an empty window as an object", function()
    t.contains(summary_format.encode(analyzer.new():summary()), '"window": {}')
  end)
end)

t.describe("analyze_lines input shapes", function()
  local LINES = { line("203.0.113.1", "/a", 200), line("203.0.113.2", "/b", 200) }

  t.it("accepts an array, an iterator and an object with lines()", function()
    t.eq(analyzer.analyze_lines(LINES).totals.requests, 2)
    local i = 0
    local iterator = function()
      i = i + 1
      return LINES[i]
    end
    t.eq(analyzer.analyze_lines(iterator).totals.requests, 2)
    local handle = { lines = function()
      return coroutine.wrap(function()
        for _, l in ipairs(LINES) do
          coroutine.yield(l)
        end
      end)
    end }
    t.eq(analyzer.analyze_lines(handle).totals.requests, 2)
  end)

  t.it("rejects anything else", function()
    t.raises(function()
      analyzer.analyze_lines(42)
    end, "iterator function")
    t.raises(function()
      analyzer.analyze_lines(nil)
    end, "iterator function")
  end)
end)

t.describe("summary document", function()
  local lines = loggen.lines({ seed = 3, count = 1200, format = "combined" })
  local s = analyzer.analyze_lines(lines, { now = 1794312189, sources = { "synthetic.log" } })

  t.it("validates and covers every section", function()
    valid(s)
    t.ok(s.latency)
    t.ok(#s.findings >= 6)
    t.ok(#s.errorSpikes >= 1)
    t.ok(#s.timeline.minute.requests > 100)
    t.eq(#s.timeline.hour.requests, 12)
  end)

  t.it("finds every scripted incident", function()
    local by_id = {}
    for _, finding in ipairs(s.findings) do
      by_id[finding.id] = finding
    end
    t.eq(by_id["scanner-agents"].count, 105)
    t.eq(by_id["sql-injection"].count, 60)
    t.eq(by_id["brute-force"].ips, { "198.51.100.203" })
    t.eq(by_id["path-traversal"].severity, "high")
    t.eq(by_id["log4shell"].count, 3)
    t.eq(by_id["xss"].count, 6)
    t.eq(by_id["rate-outlier"].ips, { "192.0.2.207" })
    t.ok(by_id["path-probing"])
    local spike = s.errorSpikes[1]
    t.ge(spike.serverErrors, 60)
  end)

  t.it("sorts findings by severity then id", function()
    local rank = { critical = 5, high = 4, medium = 3, low = 2, info = 1 }
    for i = 2, #s.findings do
      local a, b = s.findings[i - 1], s.findings[i]
      t.ok(rank[a.severity] > rank[b.severity] or (a.severity == b.severity and a.id < b.id))
    end
  end)

  t.it("encodes deterministically with the documented key order", function()
    local first = summary_format.encode(s)
    t.eq(first, summary_format.encode(s))
    t.eq(first:match('^{\n  "schema": "loglens.summary/v1",\n  "meta": {\n    "tool": "loglens"'), '{\n  "schema": "loglens.summary/v1",\n  "meta": {\n    "tool": "loglens"')
    t.matches(first, '"totals": {\n    "requests": %d+,\n    "bytes": %d+,')
  end)

  t.it("round-trips through JSON without loss", function()
    local text = summary_format.encode(s)
    local decoded, err = json.decode(text)
    t.is_nil(err)
    t.eq(decoded, s)
    valid(decoded)
    local compact = json.decode(summary_format.encode(s, { indent = 0 }))
    t.eq(compact, s)
  end)

  t.it("is safe to embed in HTML", function()
    local hostile = analyzer.analyze_lines({
      '203.0.113.1 - - [10/Nov/2026:14:03:09 +0200] "GET /</script><script>alert(1)</script> HTTP/1.1" 200 1 "-" "<b>x</b>"',
    })
    local text = summary_format.encode(hostile, { html_safe = true })
    t.not_contains(text, "<")
    t.not_contains(text, ">")
    t.eq(json.decode(text).paths[1].path, "/</script><script>alert(1)</script>")
  end)
end)

t.describe("summary validator", function()
  local good = analyzer.analyze_lines({ line("203.0.113.1", "/a", 200) })

  t.it("accepts a real summary and reports each problem with its path", function()
    valid(good)
    local copy = json.decode(summary_format.encode(good))
    copy.schema = "other/v9"
    copy.totals.requests = -1
    copy.status.classes[6] = { class = "6xx", count = 0, share = 0 }
    copy.findings = { { id = "x", title = "t", severity = "urgent", count = 1, evidence = { 1 }, limitations = {}, ips = {} } }
    copy.timeline.minute.s2xx[#copy.timeline.minute.s2xx + 1] = 5
    local ok, errors = summary_format.validate(copy)
    t.is_false(ok)
    local joined = table.concat(errors, "\n")
    t.contains(joined, "$.schema")
    t.contains(joined, "$.totals.requests")
    t.contains(joined, "$.status.classes")
    t.contains(joined, "$.findings[1].severity")
    t.contains(joined, "$.findings[1].evidence[1]")
    t.contains(joined, "series lengths differ")
  end)

  t.it("rejects non-summaries", function()
    t.is_false((summary_format.validate("nope")))
    t.is_false((summary_format.validate({})))
    t.is_false((summary_format.validate(nil)))
  end)
end)
