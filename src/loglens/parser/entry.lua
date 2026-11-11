--- Normalised request record shared by every log parser.
--
-- Parsers extract raw values from a line and hand them to `build`, which validates them, bounds
-- their size and derives `path`/`query`. Keeping this in one place guarantees that all formats
-- produce identical records.
--
-- Record fields: `ip` (string), `ts` (epoch seconds), `status` (100..599), `bytes` (>= 0) and the
-- optional `method`, `target` (raw request target, bounded), `path` (target without query or
-- fragment), `query`, `proto`, `referer`, `ua`, `rt` / `urt` (request / upstream time in
-- seconds), `proxy` (true for CONNECT or absolute-URI requests) and `invalid_request` (true when
-- the request line could not be understood).
-- @module loglens.parser.entry
local M = {}

local find, match, sub = string.find, string.match, string.sub

--- Longest request target kept (bytes); longer targets are cut.
M.MAX_TARGET = 2048
--- Longest referer / user agent kept (bytes).
M.MAX_FIELD = 1024

local MAX_ADDRESS = 255

--- Whether a string can be a client address or host name (letters, digits, `. : _ - % [ ]`).
-- @param text string
-- @return boolean
function M.valid_address(text)
  return #text > 0 and #text <= MAX_ADDRESS and not find(text, "[^%w%.:_%-%%%[%]]")
end

--- Removes a trailing `:port` from `a.b.c.d:port` or `[v6]:port`.
-- @param address string
-- @return string
function M.strip_port(address)
  local v4 = match(address, "^(%d+%.%d+%.%d+%.%d+):%d+$")
  if v4 then
    return v4
  end
  return match(address, "^%[([^%]]+)%]:?%d*$") or address
end

--- Splits `"GET /path HTTP/1.1"` into method, target and protocol.
-- Targets may contain unencoded spaces; the protocol is optional (HTTP/0.9 style).
-- @param request string
-- @return string|nil method
-- @return string|nil target
-- @return string|nil protocol
function M.split_request(request)
  local method, target, proto = match(request, "^(%a[%w_%-]*) (.+) (HTTP/%d[%d.]*)$")
  if not method then
    method, target = match(request, "^(%a[%w_%-]*) (%S+)$")
  end
  if not method or #method > 24 then
    return nil
  end
  return method, target, proto
end

local function clean_text(value)
  if type(value) ~= "string" or value == "" or value == "-" then
    return nil
  end
  if #value > M.MAX_FIELD then
    return sub(value, 1, M.MAX_FIELD)
  end
  return value
end

local function clean_seconds(value)
  if type(value) == "number" and value == value and value >= 0 and value < 1e9 then
    return value
  end
  return nil
end

--- Validates raw values and builds the normalised record.
-- @param ip string client address
-- @param ts number epoch seconds
-- @param method string|nil request method
-- @param target string|nil raw request target
-- @param proto string|nil protocol such as "HTTP/1.1"
-- @param status number|nil HTTP status
-- @param bytes number|nil response body size
-- @param referer string|nil
-- @param ua string|nil
-- @param rt number|nil request time in seconds
-- @param urt number|nil upstream time in seconds
-- @return table|nil record
-- @return string|nil reason when rejected
function M.build(ip, ts, method, target, proto, status, bytes, referer, ua, rt, urt)
  if type(ip) ~= "string" or not M.valid_address(ip) then
    return nil, "bad client address"
  end
  if math.type(status) ~= "integer" or status < 100 or status > 599 then
    return nil, "bad status code"
  end
  if math.type(bytes) ~= "integer" or bytes < 0 then
    bytes = 0
  end
  local record = {
    ip = ip,
    ts = ts,
    status = status,
    bytes = bytes,
    referer = clean_text(referer),
    ua = clean_text(ua),
    rt = clean_seconds(rt),
    urt = clean_seconds(urt),
  }
  if method and target and target ~= "" and #method <= 24 and not find(method, "[^%w_%-]") then
    if #target > M.MAX_TARGET then
      target = sub(target, 1, M.MAX_TARGET)
    end
    local path_part = target
    local authority_path = match(target, "^%a[%w+.%-]*://[^/?#]*(.*)$")
    if authority_path then
      record.proxy = true
      path_part = authority_path == "" and "/" or authority_path
    elseif method == "CONNECT" then
      record.proxy = true
    end
    local path, query = match(path_part, "^([^?#]*)%??([^#]*)")
    record.method = method
    record.target = target
    record.path = path ~= "" and path or "/"
    record.query = query ~= "" and query or nil
    record.proto = proto
  else
    record.invalid_request = true
  end
  return record
end

return M
