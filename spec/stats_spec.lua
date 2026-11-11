local t = require("spec.support")
local entry = require("loglens.parser.entry")
local lcg = require("tools.lcg")
local stats = require("loglens.stats")
local time = require("loglens.time")

-- Aligned to the minute, hour and day so timeline expectations are easy to read.
local BASE = time.parse_iso("2026-11-10T12:00:00Z")

local function rec(ip, ts, method, target, status, extra)
  extra = extra or {}
  local record = entry.build(ip, ts, method, target, "HTTP/1.1", status or 200, extra.bytes or 100,
    extra.referer, extra.ua, extra.rt, extra.urt)
  assert(record, "test record must be valid: " .. tostring(target))
  return record
end

local function new_stats(opts)
  return stats.new(opts)
end

t.describe("stats totals", function()
  t.it("summarises an empty stream", function()
    local s = new_stats():summary()
    t.eq(s.totals.requests, 0)
    t.eq(s.totals.bytes, 0)
    t.eq(s.totals.uniqueIps, 0)
    t.is_true(s.totals.uniqueIpsExact)
    t.is_nil(s.totals.firstSeen)
    t.is_nil(s.totals.peakMinute)
    t.eq(s.totals.avgRps, 0)
    t.eq(#s.paths, 0)
    t.eq(#s.status.classes, 5)
    t.eq(s.timeline.minute.requests, {})
    t.eq(s.timeline.minute.step, 60)
    t.is_nil(s.latency)
    t.eq(s.errorSpikes, {})
  end)

  t.it("counts requests, bytes, clients, time span, rates and the busiest minute", function()
    local s = new_stats()
    s:add(rec("203.0.113.1", BASE, "GET", "/a", 200, { bytes = 1000 }))
    s:add(rec("203.0.113.1", BASE + 10, "GET", "/a", 404, { bytes = 500 }))
    s:add(rec("203.0.113.2", BASE + 70, "POST", "/b", 500, { bytes = 0 }))
    s:add(rec("203.0.113.3", BASE + 75, "GET", "/a", 200, { bytes = 24 }))
    local summary = s:summary()
    local totals = summary.totals
    t.eq(totals.requests, 4)
    t.eq(totals.bytes, 1524)
    t.eq(totals.uniqueIps, 3)
    t.eq(totals.firstSeen, "2026-11-10T12:00:00Z")
    t.eq(totals.lastSeen, "2026-11-10T12:01:15Z")
    t.eq(totals.spanSeconds, 75)
    t.eq(totals.avgRps, 0.053)
    t.eq(totals.clientErrorRate, 0.25)
    t.eq(totals.serverErrorRate, 0.25)
    t.eq(totals.peakMinute, { start = "2026-11-10T12:00:00Z", requests = 2, rps = 0.033 })
    t.eq(math.type(totals.requests), "integer")
    t.eq(math.type(totals.bytes), "integer")
  end)

  t.it("handles out-of-order timestamps", function()
    local s = new_stats()
    s:add(rec("1.1.1.1", BASE + 500, "GET", "/", 200))
    s:add(rec("1.1.1.1", BASE, "GET", "/", 200))
    s:add(rec("1.1.1.1", BASE + 100, "GET", "/", 200))
    local totals = s:summary().totals
    t.eq({ totals.firstSeen, totals.lastSeen, totals.spanSeconds }, { "2026-11-10T12:00:00Z", "2026-11-10T12:08:20Z", 500 })
  end)

  t.it("treats a burst inside one second as at least one second", function()
    local s = new_stats()
    for _ = 1, 10 do
      s:add(rec("1.1.1.1", BASE, "GET", "/", 200))
    end
    t.eq(s:summary().totals.avgRps, 10)
  end)

  t.it("can be summarised repeatedly without changing", function()
    local s = new_stats()
    for i = 1, 50 do
      s:add(rec("10.0.0." .. i % 7, BASE + i, "GET", "/p" .. i % 5, 200 + (i % 3) * 100, { rt = i / 100 }))
    end
    local first = s:summary()
    t.eq(s:summary(), first)
    s:add(rec("10.0.0.99", BASE + 60, "GET", "/new", 200))
    t.eq(s:summary().totals.requests, 51)
    t.eq(first.totals.requests, 50)
  end)
end)

t.describe("stats breakdowns", function()
  t.it("breaks down status classes and codes", function()
    local s = new_stats()
    local codes = { 200, 200, 200, 301, 304, 404, 404, 500, 503, 101 }
    for i, status in ipairs(codes) do
      s:add(rec("1.1.1.1", BASE + i, "GET", "/", status))
    end
    local summary = s:summary()
    local counts = {}
    for i, class in ipairs(summary.status.classes) do
      counts[i] = class.class .. "=" .. class.count
    end
    t.eq(counts, { "1xx=1", "2xx=3", "3xx=2", "4xx=2", "5xx=2" })
    t.eq(summary.status.classes[2].share, 0.3)
    local order = {}
    for i, item in ipairs(summary.status.codes) do
      order[i] = item.code .. ":" .. item.count
    end
    t.eq(order, { "200:3", "404:2", "101:1", "301:1", "304:1", "500:1", "503:1" })
  end)

  t.it("counts methods, folding invalid and excess kinds", function()
    local s = new_stats()
    for _ = 1, 5 do
      s:add(rec("1.1.1.1", BASE, "GET", "/", 200))
    end
    for _ = 1, 3 do
      s:add(rec("1.1.1.1", BASE, "POST", "/", 200))
    end
    s:add(entry.build("1.1.1.1", BASE, nil, nil, nil, 400, 0, nil, nil))
    local summary = s:summary()
    t.eq(summary.methods[1], { method = "GET", count = 5, share = 0.5556 })
    t.eq(summary.methods[2].method, "POST")
    t.eq(summary.methods[3].method, "(invalid)")
    t.eq(summary.totals.invalidRequests, 1)

    local wide = new_stats({ top = 100 })
    for i = 1, 60 do
      wide:add(rec("1.1.1.1", BASE, "M" .. i, "/", 200))
    end
    local names = {}
    for _, item in ipairs(wide:summary().methods) do
      names[item.method] = item.count
    end
    t.eq(names["(other)"], 28)
  end)

  t.it("ranks paths without query strings and records bytes and errors", function()
    local s = new_stats()
    for i = 1, 6 do
      s:add(rec("1.1.1.1", BASE + i, "GET", "/search?q=" .. i, 200, { bytes = 10 }))
    end
    s:add(rec("1.1.1.1", BASE, "GET", "/search", 500, { bytes = 5 }))
    s:add(rec("1.1.1.1", BASE, "GET", "/about", 200))
    s:add(rec("1.1.1.1", BASE, "GET", "/about#frag", 404))
    local paths = s:summary().paths
    t.eq(paths[1], { path = "/search", count = 7, overcount = 0, bytes = 65, errors = 1 })
    t.eq(paths[2], { path = "/about", count = 2, overcount = 0, bytes = 200, errors = 1 })
  end)

  t.it("breaks count ties by path and honours the top limit", function()
    local s = new_stats({ top = 3 })
    for _, path in ipairs({ "/d", "/b", "/c", "/a", "/e" }) do
      s:add(rec("1.1.1.1", BASE, "GET", path, 200))
    end
    local seen = {}
    for i, item in ipairs(s:summary().paths) do
      seen[i] = item.path
    end
    t.eq(seen, { "/a", "/b", "/c" })
  end)

  t.it("ranks clients with errors, bytes and their busiest minute", function()
    local s = new_stats()
    for i = 1, 5 do
      s:add(rec("203.0.113.9", BASE + i, "GET", "/", i == 5 and 404 or 200, { bytes = 100 }))
    end
    s:add(rec("203.0.113.9", BASE + 130, "GET", "/", 200, { bytes = 100 }))
    s:add(rec("203.0.113.8", BASE, "GET", "/", 200))
    local clients = s:summary().clients
    t.eq(clients[1], { ip = "203.0.113.9", count = 6, overcount = 0, errors = 1, bytes = 600, peakPerMinute = 5 })
    t.eq(clients[2].ip, "203.0.113.8")
  end)

  t.it("extracts referrer hosts and ignores missing or malformed referrers", function()
    local s = new_stats()
    for _, referer in ipairs({ "https://Example.com/a", "http://example.com:8080/b", "https://user:pw@example.com/",
      "https://news.example.org/x", "-", "not a url", "android-app://com.example.app/" }) do
      s:add(rec("1.1.1.1", BASE, "GET", "/", 200, { referer = referer }))
    end
    s:add(rec("1.1.1.1", BASE, "GET", "/", 200))
    local referrers = s:summary().referrers
    t.eq(referrers[1], { host = "example.com", count = 3, overcount = 0 })
    t.eq(#referrers, 3)
  end)

  t.it("classifies user agents and keeps families", function()
    local s = new_stats()
    local chrome = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    for _ = 1, 6 do
      s:add(rec("1.1.1.1", BASE, "GET", "/", 200, { ua = chrome }))
    end
    for _ = 1, 3 do
      s:add(rec("1.1.1.2", BASE, "GET", "/", 200, { ua = "Googlebot/2.1" }))
    end
    s:add(rec("1.1.1.3", BASE, "GET", "/", 200, { ua = "curl/8.4.0" }))
    s:add(rec("1.1.1.4", BASE, "GET", "/", 200, { ua = "sqlmap/1.7" }))
    s:add(rec("1.1.1.5", BASE, "GET", "/", 200))
    local agents = s:summary().agents
    local classes = {}
    for _, item in ipairs(agents.classes) do
      classes[item.class] = item.count
    end
    t.eq(classes, { human = 6, bot = 3, tool = 1, scanner = 1, unknown = 1 })
    t.eq(agents.families[1], { name = "Chrome", class = "human", count = 6, share = 0.5 })
    t.eq(agents.families[2].name, "Googlebot")
    t.eq(agents.top[1], { agent = chrome, class = "human", family = "Chrome", count = 6, overcount = 0 })
    t.eq(#agents.top, 4)
  end)

  t.it("lists the paths behind 404 and 5xx responses", function()
    local s = new_stats()
    for _ = 1, 4 do
      s:add(rec("1.1.1.1", BASE, "GET", "/missing", 404))
    end
    s:add(rec("1.1.1.1", BASE, "GET", "/gone", 404))
    for _ = 1, 3 do
      s:add(rec("1.1.1.1", BASE, "POST", "/api/pay", 502))
    end
    s:add(rec("1.1.1.1", BASE, "GET", "/ok", 200))
    local error_paths = s:summary().errorPaths
    t.eq(error_paths.notFound[1], { path = "/missing", count = 4, overcount = 0 })
    t.eq(#error_paths.notFound, 2)
    t.eq(error_paths.serverErrors, { { path = "/api/pay", count = 3, overcount = 0 } })
  end)
end)

t.describe("stats timelines", function()
  t.it("builds dense per-minute series with class breakdown and bandwidth", function()
    local s = new_stats()
    s:add(rec("1.1.1.1", BASE, "GET", "/", 200, { bytes = 10 }))
    s:add(rec("1.1.1.1", BASE + 5, "GET", "/", 404, { bytes = 5 }))
    s:add(rec("1.1.1.1", BASE + 190, "GET", "/", 500, { bytes = 1 }))
    s:add(rec("1.1.1.1", BASE + 191, "GET", "/", 301, { bytes = 2 }))
    local minute = s:summary().timeline.minute
    t.eq(minute.start, BASE)
    t.eq(minute.step, 60)
    t.eq(minute.requests, { 2, 0, 0, 2 })
    t.eq(minute.s2xx, { 1, 0, 0, 0 })
    t.eq(minute.s3xx, { 0, 0, 0, 1 })
    t.eq(minute.s4xx, { 1, 0, 0, 0 })
    t.eq(minute.s5xx, { 0, 0, 0, 1 })
    t.eq(minute.bytes, { 15, 0, 0, 3 })
    local hour = s:summary().timeline.hour
    t.eq({ hour.start, hour.step, hour.requests }, { BASE, 3600, { 4 } })
  end)

  t.it("keeps only the newest points when the log is longer than the window", function()
    local s = new_stats({ minute_points = 10, hour_points = 3 })
    for i = 0, 29 do
      s:add(rec("1.1.1.1", BASE + i * 60, "GET", "/", 200))
    end
    for i = 0, 5 do
      s:add(rec("1.1.1.1", BASE + 7200 + i * 3600 + 5, "GET", "/", 200))
    end
    local summary = s:summary()
    t.eq(#summary.timeline.minute.requests, 10)
    t.eq(#summary.timeline.hour.requests, 3)
    t.eq(summary.timeline.hour.start, BASE + 7200 + 3 * 3600)
    t.eq(summary.totals.requests, 36)
  end)

  t.it("prunes the oldest buckets beyond the retention limit", function()
    local s = new_stats({ max_minutes = 100, minute_points = 1440 })
    for i = 0, 999 do
      s:add(rec("1.1.1.1", BASE + i * 60, "GET", "/", 200))
    end
    t.ok(s.minute_count <= 125, "buckets are pruned in batches")
    local minute = s:summary().timeline.minute
    t.ge(#minute.requests, 100)
    t.lt(#minute.requests, 126)
    t.eq(minute.requests[#minute.requests], 1)
    t.eq(minute.start + (#minute.requests - 1) * 60, BASE + 999 * 60)
    t.eq(s:summary().totals.requests, 1000)
  end)
end)

t.describe("stats latency", function()
  t.it("omits latency without request times", function()
    local s = new_stats()
    s:add(rec("1.1.1.1", BASE, "GET", "/", 200))
    t.is_nil(s:summary().latency)
  end)

  t.it("reports percentiles in milliseconds within the histogram accuracy", function()
    local s = new_stats()
    local rng = lcg.new(5)
    local values = {}
    for i = 1, 5000 do
      values[i] = math.floor(rng:lognormal(0.05, 0.9) * 1000) / 1000 + 0.001
      s:add(rec("1.1.1.1", BASE + i % 60, "GET", "/", 200, { rt = values[i], urt = values[i] / 2 }))
    end
    table.sort(values)
    local latency = s:summary().latency
    t.eq(latency.unit, "ms")
    t.eq(latency.count, 5000)
    for _, case in ipairs({ { "p50", 0.5 }, { "p90", 0.9 }, { "p95", 0.95 }, { "p99", 0.99 } }) do
      local exact = values[math.ceil(case[2] * #values)] * 1000
      t.ok(math.abs(latency[case[1]] - exact) / exact <= 0.011, case[1])
    end
    t.near(latency.max, values[#values] * 1000, 0.001)
    t.eq(latency.upstream.count, 5000)
    t.near(latency.upstream.p50, latency.p50 / 2, latency.p50 * 0.03)
  end)

  t.it("ranks the slowest endpoints that have enough timed requests", function()
    local s = new_stats({ slowest_min_count = 3 })
    for i = 1, 5 do
      s:add(rec("1.1.1.1", BASE + i, "GET", "/slow", 200, { rt = 2.0 + i / 10 }))
      s:add(rec("1.1.1.1", BASE + i, "GET", "/fast", 200, { rt = 0.01 }))
    end
    for i = 1, 2 do
      s:add(rec("1.1.1.1", BASE + i, "GET", "/rare", 200, { rt = 30 }))
    end
    s:add(rec("1.1.1.1", BASE, "GET", "/untimed", 200))
    local slowest = s:summary().latency.slowest
    t.eq(#slowest, 2, "/rare has too few samples")
    t.eq(slowest[1], { path = "/slow", count = 5, avgMs = 2300, maxMs = 2500 })
    t.eq(slowest[2].path, "/fast")
  end)
end)

t.describe("stats 5xx spikes", function()
  local function quiet_traffic(s, minutes, spike)
    for m = 0, minutes - 1 do
      for i = 1, 20 do
        local status = 200
        if i == 1 and m % 7 == 0 then
          status = 500
        end
        if spike and m >= spike.from and m <= spike.to and i <= spike.errors then
          status = 503
        end
        s:add(rec("10.0.0." .. i, BASE + m * 60 + i, "GET", "/", status))
      end
    end
  end

  t.it("detects a burst of server errors as one window", function()
    local s = new_stats()
    quiet_traffic(s, 90, { from = 50, to = 52, errors = 14 })
    local spikes = s:summary().errorSpikes
    t.eq(#spikes, 1)
    local spike = spikes[1]
    t.eq(spike.from, "2026-11-10T12:50:00Z")
    t.eq(spike.to, "2026-11-10T12:52:59Z")
    t.eq({ spike.minutes, spike.serverErrors, spike.requests, spike.peak }, { 3, 42, 60, 14 })
    t.eq(spike.rate, 0.7)
    t.ge(spike.score, 3.5)
  end)

  t.it("ignores steady background errors and tiny bursts", function()
    local steady = new_stats()
    quiet_traffic(steady, 90)
    t.eq(steady:summary().errorSpikes, {})
    local tiny = new_stats()
    quiet_traffic(tiny, 90, { from = 40, to = 40, errors = 3 })
    t.eq(tiny:summary().errorSpikes, {}, "fewer than five errors in a minute is not a spike")
  end)

  t.it("needs enough active minutes to judge", function()
    local s = new_stats()
    quiet_traffic(s, 6, { from = 3, to = 3, errors = 15 })
    t.eq(s:summary().errorSpikes, {})
  end)

  t.it("reports the worst window first", function()
    local s = new_stats()
    quiet_traffic(s, 200, { from = 40, to = 41, errors = 8 })
    for m = 150, 152 do
      for i = 1, 15 do
        s:add(rec("10.9.0." .. i, BASE + m * 60 + 30, "GET", "/", 502))
      end
    end
    local spikes = s:summary().errorSpikes
    t.eq(#spikes, 2)
    t.ge(spikes[1].serverErrors, spikes[2].serverErrors)
    t.eq(spikes[1].from, "2026-11-10T14:30:00Z")
  end)
end)

t.describe("stats bounded memory", function()
  t.it("counts unique clients exactly, then estimates beyond the exact limit", function()
    local s = new_stats({ unique_exact_limit = 200 })
    for i = 1, 150 do
      s:add(rec("10.0." .. (i // 250) .. "." .. (i % 250), BASE, "GET", "/", 200))
    end
    t.eq({ s:summary().totals.uniqueIps, s:summary().totals.uniqueIpsExact }, { 150, true })
    for i = 1, 6000 do
      s:add(rec("10.1." .. (i // 250) .. "." .. (i % 250), BASE, "GET", "/", 200))
    end
    local totals = s:summary().totals
    t.is_false(totals.uniqueIpsExact)
    t.near(totals.uniqueIps, 6150, 6150 * 0.05)
  end)

  t.it("survives a flood of random URLs, agents, referrers and clients", function()
    local s = new_stats({ capacity = 300 })
    local rng = lcg.new(99)
    collectgarbage("collect")
    local before = collectgarbage("count")
    local started = os.clock()
    for i = 1, 30000 do
      local record = rec("10." .. rng:range(0, 255) .. "." .. rng:range(0, 255) .. "." .. rng:range(0, 255), BASE + i % 3000, "GET",
        "/flood/" .. rng:next() .. "?x=" .. i, rng:pick({ 200, 404, 500 }),
        { ua = "agent-" .. rng:next(), referer = "https://h" .. rng:next() .. ".example/x" })
      s:add(record)
      if i % 3 == 0 then
        s:add(rec("203.0.113.5", BASE + i % 3000, "GET", "/popular", 200))
      end
    end
    local elapsed = os.clock() - started
    collectgarbage("collect")
    t.lt(elapsed, 8)
    t.eq(s.paths:len(), 300)
    t.eq(s.ips:len(), 300)
    t.eq(s.agent_strings:len(), 300)
    t.eq(s.referrers:len(), 300)
    t.ok(s.not_found:len() <= 300 and s.server_errors:len() <= 300)
    t.lt(collectgarbage("count") - before, 4096, "memory growth in KiB")
    local summary = s:summary()
    t.eq(summary.paths[1].path, "/popular")
    t.eq(summary.paths[1].count, 10000)
    t.eq(summary.clients[1].ip, "203.0.113.5")
    t.eq(summary.totals.requests, 40000)
  end)

  t.it("truncates very long keys", function()
    local s = new_stats({ max_path = 20, max_agent = 15, max_referrer = 12 })
    s:add(rec("1.1.1.1", BASE, "GET", "/" .. string.rep("p", 300), 200, { ua = string.rep("u", 300),
      referer = "https://" .. string.rep("h", 100) .. ".example/" }))
    local summary = s:summary()
    t.eq(#summary.paths[1].path, 20)
    t.eq(#summary.agents.top[1].agent, 15)
    t.eq(#summary.referrers[1].host, 12)
  end)

  t.it("is deterministic for a given input order", function()
    local function run()
      local s = new_stats({ capacity = 50 })
      local rng = lcg.new(1234)
      for i = 1, 3000 do
        s:add(rec("10.0.0." .. rng:range(1, 200), BASE + i, "GET", "/p" .. rng:range(1, 400), rng:pick({ 200, 404 }),
          { rt = rng:float() }))
      end
      return s:summary()
    end
    t.eq(run(), run())
  end)
end)
