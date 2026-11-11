--- Streaming statistics: one pass over the log, bounded memory.
--
-- `Stats:add(record)` folds a parsed request into counters, Space-Saving sketches (top paths,
-- clients, referrer hosts, user agents, 404 and 5xx paths), a HyperLogLog-backed unique-client
-- counter, per-minute and per-hour timelines and a log-bucket latency histogram.
-- `Stats:summary()` renders everything as plain, deterministic Lua tables (the data behind the
-- `loglens.summary/v1` JSON schema). Memory depends on the configured capacities, not on the size
-- of the log or the number of distinct URLs, addresses or user agents it contains.
-- @module loglens.stats
local agents = require("loglens.agents")
local histogram = require("loglens.histogram")
local hll = require("loglens.hll")
local time = require("loglens.time")
local topk = require("loglens.topk")
local util = require("loglens.util")

local M = {}

local sub = string.sub
local sort = table.sort
local max, min = math.max, math.min
local round = util.round

local CLASS_NAMES = { "1xx", "2xx", "3xx", "4xx", "5xx" }
local INVALID_METHOD = "(invalid)"
local OTHER_METHOD = "(other)"
local MAX_METHODS = 32

--- Default options (all overridable through `Stats.new`).
M.DEFAULTS = {
  top = 10,
  capacity = 1000,
  unique_exact_limit = 10000,
  hll_precision = 12,
  max_minutes = 10080,
  max_hours = 8760,
  minute_points = 1440,
  hour_points = 720,
  max_path = 200,
  max_agent = 200,
  max_referrer = 100,
  slowest_min_count = 5,
  latency_accuracy = 0.01,
  spike_z = 3.5,
  spike_min_count = 5,
  spike_min_minutes = 10,
}

local Stats = {}
Stats.__index = Stats

--- Creates an accumulator.
-- @param opts table|nil overrides for `M.DEFAULTS`: `top` (rows per ranked list), `capacity`
--   (tracked keys per Space-Saving list), `unique_exact_limit` / `hll_precision` (unique clients),
--   `max_minutes` / `max_hours` (retained timeline buckets), `minute_points` / `hour_points`
--   (timeline length in the summary), `max_path` / `max_agent` / `max_referrer` (key length),
--   `slowest_min_count` (timed requests an endpoint needs to be ranked), `latency_accuracy`,
--   `spike_z` / `spike_min_count` / `spike_min_minutes` (5xx spike detection)
-- @param classifier function|nil user-agent classifier (default: a fresh `agents.new_classifier()`)
-- @return table
function M.new(opts, classifier)
  local o = {}
  for key, value in pairs(M.DEFAULTS) do
    o[key] = value
  end
  for key, value in pairs(opts or {}) do
    o[key] = value
  end
  local agent_classes = {}
  for _, class in ipairs(agents.CLASSES) do
    agent_classes[class] = 0
  end
  return setmetatable({
    opts = o,
    classify = classifier or agents.new_classifier(),
    requests = 0,
    bytes = 0,
    invalid_requests = 0,
    classes = { 0, 0, 0, 0, 0 },
    codes = {},
    methods = {},
    method_kinds = 0,
    paths = topk.new(o.capacity),
    ips = topk.new(o.capacity),
    referrers = topk.new(o.capacity),
    agent_strings = topk.new(o.capacity),
    not_found = topk.new(o.capacity),
    server_errors = topk.new(o.capacity),
    unique = hll.counter(o.unique_exact_limit, o.hll_precision),
    agent_classes = agent_classes,
    families = {},
    minutes = {},
    minute_count = 0,
    hours = {},
    hour_count = 0,
    peak_requests = 0,
    latency = histogram.new({ accuracy = o.latency_accuracy }),
    upstream = histogram.new({ accuracy = o.latency_accuracy }),
    timed = 0,
  }, Stats)
end

-- Drops the oldest buckets so that at most `keep` remain.
local function prune(buckets, keep)
  local keys = {}
  for key in pairs(buckets) do
    keys[#keys + 1] = key
  end
  sort(keys)
  for i = 1, #keys - keep do
    buckets[keys[i]] = nil
  end
  return min(#keys, keep)
end

-- Timeline bucket layout: [1] requests, [2..5] 2xx..5xx, [6] bytes.
local function bucket_for(self, store_name, count_name, limit, index)
  local store = self[store_name]
  local bucket = store[index]
  if not bucket then
    bucket = { 0, 0, 0, 0, 0, 0 }
    store[index] = bucket
    self[count_name] = self[count_name] + 1
    if self[count_name] > limit + limit // 4 then
      self[count_name] = prune(store, limit)
    end
  end
  return bucket
end

local function tally(bucket, class_index, bytes)
  bucket[1] = bucket[1] + 1
  if class_index >= 2 and class_index <= 5 then
    bucket[class_index] = bucket[class_index] + 1
  end
  bucket[6] = bucket[6] + bytes
end

--- Folds one parsed request into the statistics.
-- @param e table normalised record (see `loglens.parser.entry`)
function Stats:add(e)
  local o = self.opts
  local status, bytes, ts = e.status, e.bytes, e.ts
  local class_index = status // 100

  self.requests = self.requests + 1
  self.bytes = self.bytes + bytes
  if not self.first_ts or ts < self.first_ts then
    self.first_ts = ts
  end
  if not self.last_ts or ts > self.last_ts then
    self.last_ts = ts
  end
  self.classes[class_index] = self.classes[class_index] + 1
  self.codes[status] = (self.codes[status] or 0) + 1

  local method = e.method or INVALID_METHOD
  if not self.methods[method] then
    if self.method_kinds >= MAX_METHODS then
      method = OTHER_METHOD
    end
    if not self.methods[method] then
      self.methods[method] = 0
      self.method_kinds = self.method_kinds + 1
    end
  end
  self.methods[method] = self.methods[method] + 1

  local minute, hour = ts // 60, ts // 3600
  local minute_bucket = bucket_for(self, "minutes", "minute_count", o.max_minutes, minute)
  tally(minute_bucket, class_index, bytes)
  tally(bucket_for(self, "hours", "hour_count", o.max_hours, hour), class_index, bytes)
  if minute_bucket[1] > self.peak_requests then
    self.peak_requests, self.peak_minute = minute_bucket[1], minute
  end

  local ip = e.ip
  self.unique:add(ip)
  local client, fresh_client = self.ips:add(ip)
  if fresh_client then
    client.errors, client.bytes, client.peak, client.window_count = 0, 0, 0, 0
  end
  client.bytes = client.bytes + bytes
  if status >= 400 then
    client.errors = client.errors + 1
  end
  if client.window == minute then
    client.window_count = client.window_count + 1
  else
    client.window, client.window_count = minute, 1
  end
  if client.window_count > client.peak then
    client.peak = client.window_count
  end

  local path = e.path
  if path then
    if #path > o.max_path then
      path = sub(path, 1, o.max_path)
    end
    local item, fresh_path = self.paths:add(path)
    if fresh_path then
      item.bytes, item.errors, item.timed, item.rt_sum, item.rt_max = 0, 0, 0, 0, 0
    end
    item.bytes = item.bytes + bytes
    if status >= 400 then
      item.errors = item.errors + 1
    end
    local rt = e.rt
    if rt then
      item.timed, item.rt_sum = item.timed + 1, item.rt_sum + rt
      if rt > item.rt_max then
        item.rt_max = rt
      end
    end
    if status == 404 then
      self.not_found:add(path)
    elseif status >= 500 then
      self.server_errors:add(path)
    end
  else
    self.invalid_requests = self.invalid_requests + 1
  end

  local referer = e.referer
  if referer then
    local host = util.url_host(referer)
    if host then
      self.referrers:add(#host > o.max_referrer and sub(host, 1, o.max_referrer) or host)
    end
  end

  local class, family = self.classify(e.ua)
  self.agent_classes[class] = self.agent_classes[class] + 1
  local seen = self.families[family]
  if seen then
    seen.count = seen.count + 1
  else
    -- Family names come from the fixed table in `loglens.agents`, so this map is bounded.
    self.families[family] = { count = 1, class = class }
  end
  local ua = e.ua
  if ua then
    local item, fresh_agent = self.agent_strings:add(#ua > o.max_agent and sub(ua, 1, o.max_agent) or ua)
    if fresh_agent then
      item.class, item.family = class, family
    end
  end

  local rt = e.rt
  if rt then
    self.latency:add(rt)
    self.timed = self.timed + 1
  end
  if e.urt then
    self.upstream:add(e.urt)
  end
end

--- Tracked clients with their request counts and busiest minute (used by the rate-outlier
-- heuristic).
-- @return table[] `{ key = ip, count = n, peak = max requests in one minute }` in rank order
function Stats:ip_rates()
  return self.ips:top()
end

local function share(count, total)
  if total == 0 then
    return 0
  end
  return round(count / total, 4)
end

local function ranked(sketch, limit, build)
  local out = {}
  for i, item in ipairs(sketch:top(limit)) do
    out[i] = build(item)
  end
  return out
end

local function series(buckets, last, points, step)
  local result = {
    step = step,
    start = 0,
    requests = {},
    s2xx = {},
    s3xx = {},
    s4xx = {},
    s5xx = {},
    bytes = {},
  }
  if not last then
    return result
  end
  -- Oldest retained bucket, but never more than `points` buckets before the newest one.
  local lowest = last
  for index in pairs(buckets) do
    if index < lowest then
      lowest = index
    end
  end
  local first = max(lowest, last - points + 1)
  result.start = first * step
  for index = first, last do
    local bucket = buckets[index] or { 0, 0, 0, 0, 0, 0 }
    local n = index - first + 1
    result.requests[n], result.s2xx[n], result.s3xx[n] = bucket[1], bucket[2], bucket[3]
    result.s4xx[n], result.s5xx[n], result.bytes[n] = bucket[4], bucket[5], bucket[6]
  end
  return result
end

local function latency_block(self, limit)
  local function describe(h)
    return {
      count = h:count(),
      mean = round(h:mean() * 1000, 3),
      p50 = round(h:quantile(0.5) * 1000, 3),
      p90 = round(h:quantile(0.9) * 1000, 3),
      p95 = round(h:quantile(0.95) * 1000, 3),
      p99 = round(h:quantile(0.99) * 1000, 3),
      max = round(h:max() * 1000, 3),
    }
  end
  local block = describe(self.latency)
  block.unit = "ms"
  if self.upstream:count() > 0 then
    block.upstream = describe(self.upstream)
  end
  local candidates = {}
  for _, item in ipairs(self.paths:top()) do
    if item.timed >= self.opts.slowest_min_count then
      candidates[#candidates + 1] = item
    end
  end
  sort(candidates, function(a, b)
    local avg_a, avg_b = a.rt_sum / a.timed, b.rt_sum / b.timed
    if avg_a ~= avg_b then
      return avg_a > avg_b
    end
    return a.key < b.key
  end)
  block.slowest = {}
  for i = 1, min(limit, #candidates) do
    local item = candidates[i]
    block.slowest[i] = {
      path = item.key,
      count = item.timed,
      avgMs = round(item.rt_sum / item.timed * 1000, 3),
      maxMs = round(item.rt_max * 1000, 3),
    }
  end
  return block
end

-- Windows of minutes whose 5xx count is a robust outlier (modified z-score).
local function error_spikes(self, limit)
  local o = self.opts
  local keys = {}
  for index in pairs(self.minutes) do
    keys[#keys + 1] = index
  end
  if #keys < o.spike_min_minutes then
    return {}
  end
  sort(keys)
  local counts = {}
  for i, index in ipairs(keys) do
    counts[i] = self.minutes[index][5]
  end
  local centre, scale = util.robust_scale(counts)
  if scale == 0 then
    return {}
  end
  local windows, current = {}, nil
  for _, index in ipairs(keys) do
    local bucket = self.minutes[index]
    local score = (bucket[5] - centre) / scale
    if bucket[5] >= o.spike_min_count and score >= o.spike_z then
      if current and index - current.last <= 2 then
        current.last, current.minutes = index, current.minutes + 1
      else
        current = { first = index, last = index, minutes = 1, errors = 0, requests = 0, peak = 0,
          score = 0 }
        windows[#windows + 1] = current
      end
      current.errors = current.errors + bucket[5]
      current.requests = current.requests + bucket[1]
      if bucket[5] > current.peak then
        current.peak, current.peak_at = bucket[5], index
      end
      current.score = max(current.score, score)
    end
  end
  sort(windows, function(a, b)
    if a.errors ~= b.errors then
      return a.errors > b.errors
    end
    return a.first < b.first
  end)
  local out = {}
  for i = 1, min(limit, #windows) do
    local w = windows[i]
    out[i] = {
      from = time.format_iso(w.first * 60),
      to = time.format_iso(w.last * 60 + 59),
      minutes = w.minutes,
      serverErrors = w.errors,
      requests = w.requests,
      rate = share(w.errors, w.requests),
      peak = w.peak,
      peakAt = time.format_iso(w.peak_at * 60),
      score = round(w.score, 1),
    }
  end
  return out
end

--- Builds the summary tables (deterministic ordering; safe to call repeatedly).
-- @return table `{ totals, status, methods, paths, clients, referrers, agents, errorPaths,
--   timeline, latency (when request times exist), errorSpikes }` as documented in
--   docs/json-output.md
function Stats:summary()
  local o = self.opts
  local top = o.top
  local requests = self.requests

  local span = (self.first_ts and self.last_ts) and (self.last_ts - self.first_ts) or 0
  local totals = {
    requests = requests,
    bytes = self.bytes,
    uniqueIps = self.unique:count(),
    uniqueIpsExact = self.unique:is_exact(),
    spanSeconds = span,
    avgRps = round(requests / max(1, span), 3),
    clientErrorRate = share(self.classes[4], requests),
    serverErrorRate = share(self.classes[5], requests),
    invalidRequests = self.invalid_requests,
  }
  if self.first_ts then
    totals.firstSeen = time.format_iso(self.first_ts)
    totals.lastSeen = time.format_iso(self.last_ts)
    totals.peakMinute = {
      start = time.format_iso(self.peak_minute * 60),
      requests = self.peak_requests,
      rps = round(self.peak_requests / 60, 3),
    }
  end

  local classes = {}
  for i, name in ipairs(CLASS_NAMES) do
    classes[i] = { class = name, count = self.classes[i], share = share(self.classes[i], requests) }
  end
  local codes = {}
  for code, count in pairs(self.codes) do
    codes[#codes + 1] = { code = code, count = count }
  end
  sort(codes, function(a, b)
    if a.count ~= b.count then
      return a.count > b.count
    end
    return a.code < b.code
  end)
  for i = #codes, top + 1, -1 do
    codes[i] = nil
  end

  local methods = {}
  for name, count in pairs(self.methods) do
    methods[#methods + 1] = { method = name, count = count, share = share(count, requests) }
  end
  sort(methods, function(a, b)
    if a.count ~= b.count then
      return a.count > b.count
    end
    return a.method < b.method
  end)
  for i = #methods, top + 1, -1 do
    methods[i] = nil
  end

  local agent_classes = {}
  for i, class in ipairs(agents.CLASSES) do
    agent_classes[i] = {
      class = class,
      count = self.agent_classes[class],
      share = share(self.agent_classes[class], requests),
    }
  end
  local families = {}
  for name, item in pairs(self.families) do
    families[#families + 1] = { name = name, class = item.class, count = item.count,
      share = share(item.count, requests) }
  end
  sort(families, function(a, b)
    if a.count ~= b.count then
      return a.count > b.count
    end
    return a.name < b.name
  end)
  for i = #families, top + 1, -1 do
    families[i] = nil
  end

  local result = {
    totals = totals,
    status = { classes = classes, codes = codes },
    methods = methods,
    paths = ranked(self.paths, top, function(item)
      return { path = item.key, count = item.count, overcount = item.over, bytes = item.bytes,
        errors = item.errors }
    end),
    clients = ranked(self.ips, top, function(item)
      return { ip = item.key, count = item.count, overcount = item.over, errors = item.errors,
        bytes = item.bytes, peakPerMinute = item.peak }
    end),
    referrers = ranked(self.referrers, top, function(item)
      return { host = item.key, count = item.count, overcount = item.over }
    end),
    agents = {
      classes = agent_classes,
      families = families,
      top = ranked(self.agent_strings, top, function(item)
        return { agent = item.key, class = item.class, family = item.family, count = item.count,
          overcount = item.over }
      end),
    },
    errorPaths = {
      notFound = ranked(self.not_found, top, function(item)
        return { path = item.key, count = item.count, overcount = item.over }
      end),
      serverErrors = ranked(self.server_errors, top, function(item)
        return { path = item.key, count = item.count, overcount = item.over }
      end),
    },
    timeline = {
      minute = series(self.minutes, self.last_ts and self.last_ts // 60, o.minute_points, 60),
      hour = series(self.hours, self.last_ts and self.last_ts // 3600, o.hour_points, 3600),
    },
    errorSpikes = error_spikes(self, top),
  }
  if self.timed > 0 then
    result.latency = latency_block(self, top)
  end
  return result
end

return M
