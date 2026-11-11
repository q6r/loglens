--- Parser for JSON-lines access logs (one JSON object per line).
--
-- Works with nginx `log_format ... escape=json`, Traefik-style and homegrown JSON loggers by
-- recognising common key names. Keys are compared case-insensitively with punctuation removed,
-- so `remote_addr`, `remoteAddr` and `RemoteAddr` are the same key. Within a field, earlier names
-- in the alias list win.
--
-- | field   | accepted keys (first match wins)                                                 |
-- |---------|-----------------------------------------------------------------------------------|
-- | client  | remote_addr, remote_ip, client_ip, client_addr, ip, remote_host                    |
-- | time    | time_iso8601, time_local, msec, time, timestamp, @timestamp, ts, datetime, date    |
-- | request | request ("GET /x HTTP/1.1"), request_line                                          |
-- | method  | request_method, method, http_method, verb                                          |
-- | target  | request_uri, uri, url, request_url, path, request_path, url_path                   |
-- | proto   | server_protocol, protocol, proto, http_version                                     |
-- | status  | status, status_code, response_status, http_status, code                            |
-- | bytes   | body_bytes_sent, bytes_sent, bytes, size, response_size, response_bytes             |
-- | referer | referer, referrer, http_referer, http_referrer                                     |
-- | agent   | user_agent, http_user_agent, ua, agent                                             |
-- | timing  | request_time, response_time, duration, latency, elapsed, rt (seconds)              |
-- | upstream| upstream_response_time, upstream_time, urt (seconds)                               |
--
-- Numbers may be JSON numbers or numeric strings. Time values may be epoch seconds /
-- milliseconds, ISO 8601 or Common Log Format strings.
-- @module loglens.parser.json
local entry = require("loglens.parser.entry")
local json = require("loglens.json")
local time = require("loglens.time")

local M = {}

local gsub, lower = string.gsub, string.lower

local DECODE_OPTIONS = { max_depth = 16, utf8 = "replace" }
local MEMO_LIMIT = 512
local MAX_KEY = 64 -- no alias is longer, so longer keys are never looked up or cached

local ALIASES = {
  ip = { "remoteaddr", "remoteip", "clientip", "clientaddr", "ip", "remotehost" },
  time = { "timeiso8601", "timelocal", "msec", "time", "timestamp", "ts", "datetime", "date" },
  request = { "request", "requestline" },
  method = { "requestmethod", "method", "httpmethod", "verb" },
  target = { "requesturi", "uri", "url", "requesturl", "path", "requestpath", "urlpath" },
  proto = { "serverprotocol", "protocol", "proto", "httpversion" },
  status = { "status", "statuscode", "responsestatus", "httpstatus", "code" },
  bytes = { "bodybytessent", "bytessent", "bytes", "size", "responsesize", "responsebytes" },
  referer = { "referer", "referrer", "httpreferer", "httpreferrer" },
  ua = { "useragent", "httpuseragent", "ua", "agent" },
  rt = { "requesttime", "responsetime", "duration", "latency", "elapsed", "rt" },
  urt = { "upstreamresponsetime", "upstreamtime", "urt" },
}

-- normalised key -> { field, rank }
local KEYS = {}
for field, names in pairs(ALIASES) do
  for rank, name in ipairs(names) do
    KEYS[name] = { field, rank }
  end
end

local function to_text(value)
  if type(value) == "string" then
    return value
  end
  return nil
end

local function to_integer(value)
  if type(value) == "string" then
    if value == "-" then
      return nil
    end
    value = tonumber(value)
  end
  if type(value) ~= "number" or value ~= value or value == math.huge or value == -math.huge then
    return nil
  end
  local whole = math.floor(value)
  if whole ~= value and math.type(value) == "float" then
    return nil
  end
  return math.tointeger(whole)
end

-- Seconds as a number, or the sum of the numbers in a string such as nginx's "0.001, 0.002".
local function to_seconds(value)
  if type(value) == "string" then
    local total, found = 0, false
    for number in value:gmatch("%d+%.?%d*") do
      total, found = total + tonumber(number), true
    end
    return found and total or nil
  end
  if type(value) == "number" then
    return value
  end
  return nil
end

--- Builds a parse function with its own bounded key-name cache.
-- @return function `parse(line) -> record|nil, reason`
function M.new()
  local memo, memo_size = {}, 0

  local function key_info(key)
    if #key > MAX_KEY then
      return false
    end
    local info = memo[key]
    if info == nil then
      info = KEYS[lower((gsub(key, "[^%w]", "")))] or false
      if memo_size >= MEMO_LIMIT then
        memo, memo_size = {}, 0
      end
      memo[key], memo_size = info, memo_size + 1
    end
    return info
  end

  return function(line)
    local object, err = json.decode(line, DECODE_OPTIONS)
    if object == nil then
      return nil, "invalid JSON: " .. err
    end
    if type(object) ~= "table" or object == json.null or #object > 0 then
      return nil, "JSON line is not an object"
    end
    local found, best = {}, {}
    for key, value in pairs(object) do
      local info = key_info(key)
      if info and value ~= json.null then
        local field, rank = info[1], info[2]
        if not best[field] or rank < best[field] then
          best[field], found[field] = rank, value
        end
      end
    end

    local ts, ts_error = time.parse_value(found.time)
    if not ts then
      return nil, "bad timestamp: " .. (ts_error or "missing")
    end
    local method, target, proto = to_text(found.method), to_text(found.target), to_text(found.proto)
    local request = to_text(found.request)
    if request and not (method and target) then
      local request_method, request_target, request_proto = entry.split_request(request)
      method, target = method or request_method, target or request_target
      proto = proto or request_proto
    end
    local address = to_text(found.ip)
    local referer, ua = to_text(found.referer), to_text(found.ua)
    return entry.build(address and entry.strip_port(address), ts, method, target, proto,
      to_integer(found.status), to_integer(found.bytes), referer, ua, to_seconds(found.rt),
      to_seconds(found.urt))
  end
end

return M
