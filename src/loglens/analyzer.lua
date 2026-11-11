--- The streaming analysis pipeline: log lines in, `loglens.summary/v1` table out.
--
--     local analyzer = require("loglens.analyzer").new({ format = "auto", top = 10 })
--     for line in io.lines("access.log") do analyzer:feed(line) end
--     local summary = analyzer:summary()          -- callable at any time, e.g. once per frame
--
-- The analyzer buffers the first few non-blank lines to auto-detect the format, then parses every
-- line (malformed lines are counted and sampled, never fatal), applies the optional time window
-- and feeds the statistics and security detectors. Memory use does not depend on the log size.
-- @module loglens.analyzer
local agents = require("loglens.agents")
local json = require("loglens.json")
local parser = require("loglens.parser")
local security = require("loglens.security")
local stats = require("loglens.stats")
local summary_format = require("loglens.summary")
local time = require("loglens.time")
local util = require("loglens.util")
local version = require("loglens.version")

local M = {}

local byte, find, sub = string.byte, string.find, string.sub

local DEFAULTS = {
  format = "auto",
  top = 10,
  max_line_bytes = 65536,
  malformed_samples = 5,
  detect_lines = 10,
}

local Analyzer = {}
Analyzer.__index = Analyzer

local function to_epoch(value, name)
  if value == nil then
    return nil
  end
  local epoch, err = time.parse_value(value)
  if not epoch then
    error(string.format("invalid '%s' value %s: %s", name, tostring(value), err), 3)
  end
  return epoch
end

--- Creates an analyzer.
-- @param opts table|nil
--   `format` "auto" (default), "combined", "common", "json" or "caddy";
--   `top` rows per ranked list (default 10);
--   `from` / `to` inclusive time window, epoch seconds or ISO 8601 strings;
--   `sources` array of display names for `meta.sources` (or `source` string);
--   `now` epoch seconds recorded as `meta.generatedAt` (omitted when nil);
--   `max_line_bytes` lines longer than this are counted as malformed (default 65536);
--   `malformed_samples` how many malformed lines to keep as examples (default 5);
--   `detect_lines` non-blank lines buffered for format detection (default 10);
--   `stats` / `security` option tables passed to the respective modules
-- @return table analyzer
function M.new(opts)
  opts = opts or {}
  local o = {}
  for key, value in pairs(DEFAULTS) do
    o[key] = value
  end
  for key, value in pairs(opts) do
    o[key] = value
  end
  local stats_options = {}
  for key, value in pairs(opts.stats or {}) do
    stats_options[key] = value
  end
  stats_options.top = stats_options.top or o.top

  local classifier = agents.new_classifier()
  local self = setmetatable({
    opts = o,
    stats = stats.new(stats_options, classifier),
    security = security.new(opts.security, classifier),
    from = to_epoch(o.from, "from"),
    to = to_epoch(o.to, "to"),
    total = 0,
    parsed = 0,
    malformed = 0,
    blank = 0,
    outside = 0,
    samples = {},
    pending = {},
    auto_detected = false,
  }, Analyzer)
  if o.from and o.to and self.from > self.to then
    error("'from' must not be later than 'to'", 2)
  end
  if o.format ~= "auto" then
    local parse, err = parser.get(o.format)
    if not parse then
      error(err, 2)
    end
    self.format, self.parse = o.format, parse
  end
  return self
end

function Analyzer:reject(number, line, reason)
  self.malformed = self.malformed + 1
  if #self.samples < self.opts.malformed_samples then
    self.samples[#self.samples + 1] = {
      line = number,
      reason = reason,
      preview = util.defang(line, 160),
    }
  end
end

function Analyzer:process(number, line)
  local ok, record, reason = pcall(self.parse, line)
  if not ok then
    self:reject(number, line, "parser error: " .. tostring(record))
    return
  end
  if not record then
    self:reject(number, line, reason)
    return
  end
  self.parsed = self.parsed + 1
  local ts = record.ts
  if (self.from and ts < self.from) or (self.to and ts > self.to) then
    self.outside = self.outside + 1
    return
  end
  self.stats:add(record)
  self.security:observe(record)
end

-- Decides the format from the buffered lines and replays them through the pipeline.
function Analyzer:resolve_format()
  local sample = {}
  for i, item in ipairs(self.pending) do
    sample[i] = item[2]
  end
  local name = parser.detect(sample)
  self.auto_detected = name ~= nil
  self.format = name or "combined"
  self.parse = parser.get(self.format)
  local pending = self.pending
  self.pending = {}
  for _, item in ipairs(pending) do
    self:process(item[1], item[2])
  end
end

--- Feeds one line of the log (with or without its line terminator).
-- @param line string
function Analyzer:feed(line)
  self.total = self.total + 1
  local number = self.total
  if byte(line, -1) == 13 then
    line = sub(line, 1, -2)
  end
  if number == 1 and sub(line, 1, 3) == "\239\187\191" then
    line = sub(line, 4)
  end
  if not find(line, "%S") then
    self.blank = self.blank + 1
    return
  end
  if #line > self.opts.max_line_bytes then
    self:reject(number, sub(line, 1, 200), "line too long (over " .. self.opts.max_line_bytes .. " bytes)")
    return
  end
  if self.parse then
    self:process(number, line)
    return
  end
  self.pending[#self.pending + 1] = { number, line }
  if #self.pending >= self.opts.detect_lines then
    self:resolve_format()
  end
end

local function iso(epoch)
  return epoch and time.format_iso(epoch) or nil
end

--- Builds the summary table. Safe to call repeatedly while feeding (for live views); lines
-- still waiting for format detection are resolved first.
-- @return table the `loglens.summary/v1` document (see docs/json-output.md)
function Analyzer:summary()
  if not self.parse and #self.pending > 0 then
    self:resolve_format()
  end
  local o = self.opts
  local result = self.stats:summary()
  local now = o.now
  if type(now) == "function" then
    now = now()
  end
  local sources = o.sources or (o.source and { o.source }) or {}
  local samples = {}
  for i, sample in ipairs(self.samples) do
    samples[i] = { line = sample.line, reason = sample.reason, preview = sample.preview }
  end
  result.schema = summary_format.SCHEMA
  result.meta = {
    tool = "loglens",
    version = version,
    generatedAt = iso(now),
    sources = sources,
    format = self.format or "unknown",
    autoDetected = self.auto_detected,
    lines = {
      total = self.total,
      parsed = self.parsed,
      malformed = self.malformed,
      blank = self.blank,
      outsideWindow = self.outside,
    },
    window = json.object({ from = iso(self.from), to = iso(self.to) }),
    limits = {
      topCapacity = self.stats.opts.capacity,
      uniqueExactLimit = self.stats.opts.unique_exact_limit,
      maxLineBytes = o.max_line_bytes,
      minuteBuckets = self.stats.opts.max_minutes,
      hourBuckets = self.stats.opts.max_hours,
    },
    malformedSamples = samples,
  }
  result.findings = self.security:findings({
    ip_rates = self.stats:ip_rates(),
    requests = self.stats.requests,
  })
  return result
end

--- Convenience: analyses a whole sequence of lines.
-- @param source function|table|userdata an iterator returning lines, an array of lines, or
--   anything with a `lines()` method (such as an open file)
-- @param opts table|nil see `new`
-- @return table summary
function M.analyze_lines(source, opts)
  local analyzer = M.new(opts)
  local kind = type(source)
  if kind == "function" then
    for line in source do
      analyzer:feed(line)
    end
  elseif (kind == "table" or kind == "userdata") and type(source.lines) == "function" then
    for line in source:lines() do
      analyzer:feed(line)
    end
  elseif kind == "table" then
    for _, line in ipairs(source) do
      analyzer:feed(line)
    end
  else
    error("analyze_lines expects an iterator function, an array of lines or a file", 2)
  end
  return analyzer:summary()
end

return M
