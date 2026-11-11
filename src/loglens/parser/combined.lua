--- Parser for nginx / Apache "common" and "combined" access logs.
--
--     203.0.113.9 - alice [10/Nov/2026:14:03:09 +0200] "GET /a?b=1 HTTP/1.1" 200 512 "https://x/" "UA" 0.123 0.100
--
-- A hand-written tokenizer (no regular expression for the whole line) that tolerates what real
-- logs contain: IPv6 addresses, `-` placeholders, user names with spaces, escaped quotes
-- (`\"`, `\\`, nginx `\x22`), unencoded spaces in request targets, binary garbage in the request
-- line, `ip:port` clients, Apache `vhost:port` prefixes and truncated lines. The combined format
-- also accepts trailing `request_time [upstream_response_time ...]` numbers (seconds) and ignores
-- extra quoted fields such as `X-Forwarded-For`.
--
-- A line is rejected only when a core field (client, timestamp, request, status) is unusable.
-- @module loglens.parser.combined
local entry = require("loglens.parser.entry")
local time = require("loglens.time")

local M = {}

local byte, char, find, match, sub = string.byte, string.char, string.find, string.match, string.sub
local concat = table.concat

-- Decodes `\"`, `\\`, `\n`, `\r`, `\t` and `\xNN`; other backslashes are kept as they are.
local function unescape(text)
  if not find(text, "\\", 1, true) then
    return text
  end
  local out, n, pos = {}, 0, 1
  while true do
    local at = find(text, "\\", pos, true)
    if not at then
      out[n + 1] = sub(text, pos)
      break
    end
    if at > pos then
      n = n + 1
      out[n] = sub(text, pos, at - 1)
    end
    local c = sub(text, at + 1, at + 1)
    n = n + 1
    if c == '"' or c == "\\" then
      out[n], pos = c, at + 2
    elseif c == "n" then
      out[n], pos = "\n", at + 2
    elseif c == "r" then
      out[n], pos = "\r", at + 2
    elseif c == "t" then
      out[n], pos = "\t", at + 2
    elseif c == "x" and find(text, "^%x%x", at + 2) then
      out[n], pos = char(tonumber(sub(text, at + 2, at + 3), 16)), at + 4
    else
      out[n], pos = "\\", at + 1
    end
  end
  return concat(out)
end

-- Reads the double-quoted field starting at `pos`. Returns the decoded text and the position
-- after the closing quote, or nil when the field is not terminated (truncated line).
local function scan_quoted(line, pos)
  local i = pos + 1
  while true do
    local at = find(line, '["\\]', i)
    if not at then
      return nil
    end
    if byte(line, at) == 34 then
      return unescape(sub(line, pos + 1, at - 1)), at + 1
    end
    i = at + 2
  end
end

-- Sum of the decimal numbers in a token list such as "0.001, 0.002" or "-".
local function sum_numbers(tokens, from)
  local total, found = 0, false
  for i = from, #tokens do
    for number in tokens[i]:gmatch("%d+%.?%d*") do
      total = total + tonumber(number)
      found = true
    end
  end
  return found and total or nil
end

-- Bare tokens after the user agent: request_time and upstream times. Extra quoted fields are
-- skipped. Returns request_time, upstream_time (seconds) or nils.
local function parse_trailer(line, pos)
  local tokens = {}
  while #tokens < 8 do
    local start = find(line, "%S", pos)
    if not start then
      break
    end
    if byte(line, start) == 34 then
      local _, after = scan_quoted(line, start)
      if not after then
        break
      end
      pos = after
    else
      local finish = find(line, "%s", start) or (#line + 1)
      tokens[#tokens + 1] = sub(line, start, finish - 1)
      pos = finish
    end
  end
  local request_time
  if tokens[1] and match(tokens[1], "^%d+%.?%d*$") then
    request_time = tonumber(tokens[1])
  end
  return request_time, request_time and sum_numbers(tokens, 2) or nil
end

local function parse_line(line, extended)
  if find(line, "\0", 1, true) then
    return nil, "binary data (NUL byte)"
  end
  local open = find(line, " [", 1, true)
  if not open then
    return nil, "missing [timestamp]"
  end
  local close = find(line, "]", open + 2, true)
  if not close then
    return nil, "unterminated [timestamp]"
  end
  local ts = time.parse_clf(sub(line, open + 2, close - 1))
  if not ts then
    return nil, "bad timestamp"
  end

  local first, rest = match(sub(line, 1, open - 1), "^%s*(%S+)%s*(.*)$")
  if not first then
    return nil, "missing client address"
  end
  local ip
  local second = match(rest, "^(%S+)")
  if second and second ~= "-" and match(first, "^[%w._%-]+:%d+$") and entry.valid_address(second) then
    ip = second
  else
    ip = entry.strip_port(first)
  end

  local quote = find(line, "%S", close + 1)
  if not quote or byte(line, quote) ~= 34 then
    return nil, "missing request field"
  end
  local request, after = scan_quoted(line, quote)
  if not request then
    return nil, "unterminated request field"
  end
  local status_text, after_status = match(line, "^%s+(%d%d%d)()", after)
  if not status_text then
    return nil, "bad status code"
  end
  local status = tonumber(status_text)
  local bytes_text, after_bytes = match(line, "^%s+(%S+)()", after_status)
  local bytes = 0
  if bytes_text and bytes_text ~= "-" then
    if #bytes_text > 15 or not match(bytes_text, "^%d+$") then
      return nil, "bad byte count"
    end
    bytes = tonumber(bytes_text)
  end

  local method, target, proto = entry.split_request(request)
  local referer, ua, request_time, upstream_time
  local has_quoted_fields = false
  if extended and after_bytes then
    local q1 = find(line, "%S", after_bytes)
    if q1 and byte(line, q1) == 34 then
      has_quoted_fields = true
      local value, next_pos = scan_quoted(line, q1)
      if value then
        referer = value
        local q2 = find(line, "%S", next_pos)
        if q2 and byte(line, q2) == 34 then
          ua, next_pos = scan_quoted(line, q2)
        end
        if next_pos then
          request_time, upstream_time = parse_trailer(line, next_pos)
        end
      end
    end
  end

  local record, reason = entry.build(ip, ts, method, target, proto, status, bytes, referer, ua,
    request_time, upstream_time)
  if record and has_quoted_fields then
    record.extended = true
  end
  return record, reason
end

--- Parses one line of a combined-format log (referer, user agent and timings are optional).
-- @param line string
-- @return table|nil record (see `loglens.parser.entry`; `extended` is true when referer/user
--   agent fields were present)
-- @return string|nil reason when the line is rejected
function M.parse(line)
  return parse_line(line, true)
end

--- Parses one line of a common-format log: everything after the byte count is ignored.
-- @param line string
-- @return table|nil record
-- @return string|nil reason
function M.parse_common(line)
  return parse_line(line, false)
end

return M
