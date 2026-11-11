--- The `loglens.summary/v1` document: schema id, canonical JSON encoding and a validator.
--
-- The summary is plain data (nested tables). `encode` serialises it deterministically (fixed key
-- order, sorted arrays are produced by the analyzer), so the same log always yields the same
-- bytes. `validate` checks the structure documented in docs/json-output.md and is used by the
-- test suite and by renderers that want to reject foreign input.
-- @module loglens.summary
local json = require("loglens.json")

local M = {}

--- Identifier stored in every summary under `schema`.
M.SCHEMA = "loglens.summary/v1"

--- Preferred key order for the JSON encoding (everything else follows alphabetically).
M.KEY_ORDER = {
  -- document
  "schema", "meta", "totals", "status", "methods", "paths", "clients", "referrers", "agents",
  "errorPaths", "timeline", "latency", "errorSpikes", "findings",
  -- meta
  "tool", "version", "generatedAt", "sources", "format", "autoDetected", "lines", "window",
  "limits", "malformedSamples", "total", "parsed", "malformed", "blank", "outsideWindow",
  -- identity of list entries
  "id", "title", "severity", "path", "ip", "host", "agent", "method", "code", "class", "family",
  "name", "line", "reason", "preview", "from", "to", "unit",
  -- measures
  "count", "share", "overcount", "errors", "start", "step", "minutes", "serverErrors", "requests",
  "s2xx", "s3xx", "s4xx", "s5xx", "bytes", "uniqueIps", "uniqueIpsExact", "firstSeen",
  "lastSeen", "spanSeconds", "avgRps", "peakMinute", "rps", "clientErrorRate",
  "serverErrorRate", "invalidRequests", "peakPerMinute", "mean", "p50", "p90", "p95", "p99", "max",
  "avgMs", "maxMs", "upstream", "slowest", "rate", "peak", "peakAt", "score", "evidence",
  "limitations",
}

local SEVERITIES = { info = true, low = true, medium = true, high = true, critical = true }
local AGENT_CLASSES = { human = true, bot = true, tool = true, scanner = true, unknown = true }

--- Serialises a summary as JSON.
-- @param summary table
-- @param opts table|nil `{ indent = 2, html_safe = false }`; `indent` defaults to 2 (pass 0 for
--   compact output); `html_safe` escapes `< > &` so the text can sit inside a `<script>` element
-- @return string
function M.encode(summary, opts)
  opts = opts or {}
  local indent = opts.indent
  if indent == nil then
    indent = 2
  end
  return json.encode(summary, {
    indent = indent,
    key_order = M.KEY_ORDER,
    html_safe = opts.html_safe,
  })
end

local Checker = {}
Checker.__index = Checker

local function new_checker()
  return setmetatable({ errors = {} }, Checker)
end

function Checker:fail(path, message)
  self.errors[#self.errors + 1] = path .. ": " .. message
end

function Checker:table(value, path)
  if type(value) ~= "table" then
    self:fail(path, "expected a table, got " .. type(value))
    return false
  end
  return true
end

function Checker:integer(value, path, minimum)
  if math.type(value) ~= "integer" or value < (minimum or 0) then
    self:fail(path, "expected an integer >= " .. (minimum or 0))
    return false
  end
  return true
end

function Checker:number(value, path, minimum)
  if type(value) ~= "number" or value ~= value or value < (minimum or 0) then
    self:fail(path, "expected a number >= " .. (minimum or 0))
    return false
  end
  return true
end

function Checker:string(value, path)
  if type(value) ~= "string" then
    self:fail(path, "expected a string")
    return false
  end
  return true
end

function Checker:optional_string(value, path)
  return value == nil or self:string(value, path)
end

function Checker:list(value, path, each)
  if not self:table(value, path) then
    return
  end
  for i = 1, #value do
    each(self, value[i], path .. "[" .. i .. "]")
  end
  for key in pairs(value) do
    if math.type(key) ~= "integer" or key < 1 or key > #value then
      self:fail(path, "expected an array (found key " .. tostring(key) .. ")")
      break
    end
  end
end

local function check_ranked(c, item, path, key)
  if c:table(item, path) then
    c:string(item[key], path .. "." .. key)
    c:integer(item.count, path .. ".count")
    c:integer(item.overcount, path .. ".overcount")
  end
end

local function check_strings(c, value, path)
  c:string(value, path)
end

local function check_series(c, series, path)
  if not c:table(series, path) then
    return
  end
  c:integer(series.step, path .. ".step", 1)
  c:integer(series.start, path .. ".start")
  local length
  for _, key in ipairs({ "requests", "s2xx", "s3xx", "s4xx", "s5xx", "bytes" }) do
    c:list(series[key], path .. "." .. key, function(checker, value, where)
      checker:integer(value, where)
    end)
    local n = type(series[key]) == "table" and #series[key] or 0
    if length and n ~= length then
      c:fail(path .. "." .. key, "series lengths differ")
    end
    length = length or n
  end
end

local function check_latency_block(c, block, path)
  if not c:table(block, path) then
    return
  end
  c:integer(block.count, path .. ".count")
  for _, key in ipairs({ "mean", "p50", "p90", "p95", "p99", "max" }) do
    c:number(block[key], path .. "." .. key)
  end
end

--- Validates a summary against the `loglens.summary/v1` structure.
-- @param summary table
-- @return boolean ok
-- @return string[]|nil error messages (each prefixed with the path of the offending field)
function M.validate(summary)
  local c = new_checker()
  if not c:table(summary, "$") then
    return false, c.errors
  end
  if summary.schema ~= M.SCHEMA then
    c:fail("$.schema", "expected " .. M.SCHEMA)
  end

  local meta = summary.meta
  if c:table(meta, "$.meta") then
    c:string(meta.tool, "$.meta.tool")
    c:string(meta.version, "$.meta.version")
    c:optional_string(meta.generatedAt, "$.meta.generatedAt")
    c:list(meta.sources, "$.meta.sources", check_strings)
    c:string(meta.format, "$.meta.format")
    if type(meta.autoDetected) ~= "boolean" then
      c:fail("$.meta.autoDetected", "expected a boolean")
    end
    if c:table(meta.lines, "$.meta.lines") then
      for _, key in ipairs({ "total", "parsed", "malformed", "blank", "outsideWindow" }) do
        c:integer(meta.lines[key], "$.meta.lines." .. key)
      end
    end
    if c:table(meta.window, "$.meta.window") then
      c:optional_string(meta.window.from, "$.meta.window.from")
      c:optional_string(meta.window.to, "$.meta.window.to")
    end
    c:table(meta.limits, "$.meta.limits")
    c:list(meta.malformedSamples, "$.meta.malformedSamples", function(checker, item, path)
      if checker:table(item, path) then
        checker:integer(item.line, path .. ".line", 1)
        checker:string(item.reason, path .. ".reason")
        checker:string(item.preview, path .. ".preview")
      end
    end)
  end

  local totals = summary.totals
  if c:table(totals, "$.totals") then
    for _, key in ipairs({ "requests", "bytes", "uniqueIps", "spanSeconds", "invalidRequests" }) do
      c:integer(totals[key], "$.totals." .. key)
    end
    if type(totals.uniqueIpsExact) ~= "boolean" then
      c:fail("$.totals.uniqueIpsExact", "expected a boolean")
    end
    for _, key in ipairs({ "avgRps", "clientErrorRate", "serverErrorRate" }) do
      c:number(totals[key], "$.totals." .. key)
    end
    c:optional_string(totals.firstSeen, "$.totals.firstSeen")
    c:optional_string(totals.lastSeen, "$.totals.lastSeen")
    if (totals.requests or 0) > 0 and totals.firstSeen == nil then
      c:fail("$.totals.firstSeen", "required when requests > 0")
    end
  end

  local status = summary.status
  if c:table(status, "$.status") then
    c:list(status.classes, "$.status.classes", function(checker, item, path)
      if checker:table(item, path) then
        checker:string(item.class, path .. ".class")
        checker:integer(item.count, path .. ".count")
        checker:number(item.share, path .. ".share")
      end
    end)
    if type(status.classes) == "table" and #status.classes ~= 5 then
      c:fail("$.status.classes", "expected 5 entries (1xx..5xx)")
    end
    c:list(status.codes, "$.status.codes", function(checker, item, path)
      if checker:table(item, path) then
        checker:integer(item.code, path .. ".code", 100)
        checker:integer(item.count, path .. ".count")
      end
    end)
  end

  c:list(summary.methods, "$.methods", function(checker, item, path)
    if checker:table(item, path) then
      checker:string(item.method, path .. ".method")
      checker:integer(item.count, path .. ".count")
      checker:number(item.share, path .. ".share")
    end
  end)
  c:list(summary.paths, "$.paths", function(checker, item, path)
    check_ranked(checker, item, path, "path")
  end)
  c:list(summary.clients, "$.clients", function(checker, item, path)
    check_ranked(checker, item, path, "ip")
  end)
  c:list(summary.referrers, "$.referrers", function(checker, item, path)
    check_ranked(checker, item, path, "host")
  end)

  local agents = summary.agents
  if c:table(agents, "$.agents") then
    c:list(agents.classes, "$.agents.classes", function(checker, item, path)
      if checker:table(item, path) then
        if not AGENT_CLASSES[item.class] then
          checker:fail(path .. ".class", "unknown agent class")
        end
        checker:integer(item.count, path .. ".count")
      end
    end)
    c:list(agents.families, "$.agents.families", function(checker, item, path)
      if checker:table(item, path) then
        checker:string(item.name, path .. ".name")
        checker:integer(item.count, path .. ".count")
      end
    end)
    c:list(agents.top, "$.agents.top", function(checker, item, path)
      check_ranked(checker, item, path, "agent")
    end)
  end

  local error_paths = summary.errorPaths
  if c:table(error_paths, "$.errorPaths") then
    for _, key in ipairs({ "notFound", "serverErrors" }) do
      c:list(error_paths[key], "$.errorPaths." .. key, function(checker, item, path)
        check_ranked(checker, item, path, "path")
      end)
    end
  end

  local timeline = summary.timeline
  if c:table(timeline, "$.timeline") then
    check_series(c, timeline.minute, "$.timeline.minute")
    check_series(c, timeline.hour, "$.timeline.hour")
  end

  if summary.latency ~= nil and c:table(summary.latency, "$.latency") then
    local latency = summary.latency
    check_latency_block(c, latency, "$.latency")
    if latency.unit ~= "ms" then
      c:fail("$.latency.unit", "expected ms")
    end
    if latency.upstream ~= nil then
      check_latency_block(c, latency.upstream, "$.latency.upstream")
    end
    c:list(latency.slowest, "$.latency.slowest", function(checker, item, path)
      if checker:table(item, path) then
        checker:string(item.path, path .. ".path")
        checker:integer(item.count, path .. ".count")
        checker:number(item.avgMs, path .. ".avgMs")
        checker:number(item.maxMs, path .. ".maxMs")
      end
    end)
  end

  c:list(summary.errorSpikes, "$.errorSpikes", function(checker, item, path)
    if checker:table(item, path) then
      checker:string(item.from, path .. ".from")
      checker:string(item.to, path .. ".to")
      checker:integer(item.serverErrors, path .. ".serverErrors")
      checker:integer(item.requests, path .. ".requests")
    end
  end)

  c:list(summary.findings, "$.findings", function(checker, item, path)
    if not checker:table(item, path) then
      return
    end
    checker:string(item.id, path .. ".id")
    checker:string(item.title, path .. ".title")
    if not SEVERITIES[item.severity] then
      checker:fail(path .. ".severity", "unknown severity")
    end
    checker:integer(item.count, path .. ".count")
    checker:list(item.evidence, path .. ".evidence", check_strings)
    checker:list(item.limitations, path .. ".limitations", check_strings)
    checker:list(item.ips, path .. ".ips", check_strings)
  end)

  if #c.errors > 0 then
    return false, c.errors
  end
  return true
end

return M
