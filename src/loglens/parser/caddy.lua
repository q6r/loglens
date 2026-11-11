--- Parser for Caddy v2 JSON access logs.
--
-- Caddy writes one JSON object per request with the request nested under `request`:
--
--     {"level":"info","ts":1646861401.52,"logger":"http.log.access.log0","msg":"handled request",
--      "request":{"remote_ip":"203.0.113.9","client_ip":"203.0.113.9","proto":"HTTP/2.0",
--      "method":"GET","host":"example.com","uri":"/a?b=1","headers":{"User-Agent":["curl/8"]}},
--      "duration":0.0009,"size":10900,"status":200}
--
-- The client is `client_ip` (falling back to `remote_ip` / `remote_addr`), the time is `ts`
-- (epoch seconds, or whatever string `time_format` produces), the latency is `duration`
-- (seconds) and the response size is `size`. Records without `request` and a numeric `status`
-- (error log lines that share the file) are rejected as "not a Caddy access record".
-- @module loglens.parser.caddy
local entry = require("loglens.parser.entry")
local json = require("loglens.json")
local time = require("loglens.time")

local M = {}

local lower = string.lower

local DECODE_OPTIONS = { max_depth = 16, utf8 = "replace" }

-- First value of a header, matching the name case-insensitively (Caddy canonicalises names, but
-- other loggers do not).
local function header(headers, name)
  if type(headers) ~= "table" then
    return nil
  end
  local value = headers[name]
  if value == nil then
    local wanted = lower(name)
    for key, candidate in pairs(headers) do
      if type(key) == "string" and lower(key) == wanted then
        value = candidate
        break
      end
    end
  end
  if type(value) == "table" then
    value = value[1]
  end
  if type(value) == "string" then
    return value
  end
  return nil
end

local function first_string(...)
  for i = 1, select("#", ...) do
    local value = select(i, ...)
    if type(value) == "string" and value ~= "" then
      return value
    end
  end
  return nil
end

--- Parses one Caddy access-log line.
-- @param line string
-- @return table|nil record (see `loglens.parser.entry`)
-- @return string|nil reason when the line is rejected
function M.parse(line)
  local object, err = json.decode(line, DECODE_OPTIONS)
  if object == nil then
    return nil, "invalid JSON: " .. err
  end
  if type(object) ~= "table" or type(object.request) ~= "table" or object.request == json.null
      or type(object.status) ~= "number" then
    return nil, "not a Caddy access record"
  end
  local request = object.request
  local ts, ts_error = time.parse_value(object.ts)
  if not ts then
    return nil, "bad timestamp: " .. (ts_error or "missing")
  end
  local address = first_string(request.client_ip, request.remote_ip, request.remote_addr)
  local status = object.status
  if status ~= math.floor(status) then
    return nil, "bad status code"
  end
  local size = type(object.size) == "number" and math.floor(object.size) or nil
  local duration = type(object.duration) == "number" and object.duration or nil
  local method = type(request.method) == "string" and request.method or nil
  local target = type(request.uri) == "string" and request.uri or nil
  local proto = type(request.proto) == "string" and request.proto or nil
  return entry.build(address and entry.strip_port(address), ts, method, target, proto,
    math.tointeger(math.floor(status)), size and math.tointeger(size),
    header(request.headers, "Referer"), header(request.headers, "User-Agent"), duration, nil)
end

return M
