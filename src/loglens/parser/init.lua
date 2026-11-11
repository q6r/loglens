--- Log format registry and auto-detection.
--
-- Every parser has the same shape: `parse(line) -> record | nil, reason`, where `record` is the
-- normalised request described in `loglens.parser.entry`. Parsers never raise on bad input.
-- @module loglens.parser
local caddy = require("loglens.parser.caddy")
local combined = require("loglens.parser.combined")
local json_lines = require("loglens.parser.json")

local M = {}

local find, match = string.find, string.match

--- Supported formats in detection-friendly order, with documentation used by `loglens formats`.
M.FORMATS = {
  {
    name = "combined",
    description = "nginx / Apache combined log format; trailing request_time [upstream_time] "
      .. "(seconds) are read when present, and the common format is accepted too",
    example = '203.0.113.9 - - [10/Nov/2026:14:03:09 +0000] "GET /a?b=1 HTTP/1.1" 200 512 '
      .. '"https://example.com/" "Mozilla/5.0" 0.123',
  },
  {
    name = "common",
    description = "Common Log Format (no referer / user agent); anything after the byte count "
      .. "is ignored",
    example = '203.0.113.9 - frank [10/Nov/2026:14:03:09 +0000] "GET /a HTTP/1.0" 200 2326',
  },
  {
    name = "json",
    description = "JSON lines with common key names (remote_addr, request_uri, status, "
      .. "body_bytes_sent, request_time ...)",
    example = '{"remote_addr":"203.0.113.9","time_iso8601":"2026-11-10T14:03:09+00:00",'
      .. '"request_method":"GET","request_uri":"/a?b=1","status":200,"body_bytes_sent":512}',
  },
  {
    name = "caddy",
    description = "Caddy v2 JSON access logs (request.client_ip, request.uri, ts, duration, size)",
    example = '{"ts":1762783389.5,"request":{"client_ip":"203.0.113.9","method":"GET",'
      .. '"uri":"/a","headers":{"User-Agent":["curl/8"]}},"duration":0.002,"size":512,"status":200}',
  },
}

--- Names accepted by `--format` (besides "auto").
-- @return string[]
function M.names()
  local names = {}
  for i, format in ipairs(M.FORMATS) do
    names[i] = format.name
  end
  return names
end

--- Returns a parse function for a format name. Each call returns an independent function, so
-- parsers that keep a private cache do not share state.
-- @param name string "combined", "common", "json" or "caddy"
-- @return function|nil parse
-- @return string|nil error message for an unknown name
function M.get(name)
  if name == "combined" then
    return combined.parse
  elseif name == "common" then
    return combined.parse_common
  elseif name == "json" then
    return json_lines.new()
  elseif name == "caddy" then
    return caddy.parse
  end
  return nil, "unknown format '" .. tostring(name) .. "'"
end

--- Detects the format from sample lines (blank lines are ignored).
-- Each non-blank line votes for the formats that can parse it; JSON objects vote for "caddy"
-- when they look like Caddy access records and for "json" otherwise, text lines vote for
-- "combined" when they carry referer / user-agent fields and for "common" otherwise.
-- @param lines string[] the first lines of the log
-- @return string|nil name, or nil when no line could be parsed
-- @return table info `{ sampled = number, matched = number }`
function M.detect(lines)
  local parse_json = json_lines.new()
  local votes = { caddy = 0, json = 0, combined = 0, common = 0 }
  local sampled = 0
  for _, line in ipairs(lines) do
    if find(line, "%S") then
      sampled = sampled + 1
      if match(line, "^%s*(.)") == "{" then
        if caddy.parse(line) then
          votes.caddy = votes.caddy + 1
        elseif parse_json(line) then
          votes.json = votes.json + 1
        end
      else
        local record = combined.parse(line)
        if record then
          local name = record.extended and "combined" or "common"
          votes[name] = votes[name] + 1
        end
      end
    end
  end
  local structured = votes.caddy + votes.json
  local text = votes.combined + votes.common
  local info = { sampled = sampled, matched = math.max(structured, text) }
  if info.matched == 0 then
    return nil, info
  end
  if structured > text then
    return (votes.caddy >= votes.json) and "caddy" or "json", info
  end
  return (votes.combined > 0) and "combined" or "common", info
end

return M
