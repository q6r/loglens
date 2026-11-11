--- Strict, dependency-free JSON decoder and encoder (RFC 8259).
--
-- Decoder: rejects trailing commas, leading zeros, bad escapes, unescaped control characters,
-- unpaired surrogates, NaN/Infinity, trailing garbage and nesting deeper than `max_depth`.
-- It never raises on bad input: `decode` returns `nil, message`.
--
-- Encoder: deterministic (object keys are always sorted, optionally after a preferred order),
-- refuses NaN/Infinity, repairs invalid UTF-8 and can escape `< > &` for embedding in HTML.
-- @module loglens.json
local util = require("loglens.util")

local M = {}

local byte, char, find, format, gsub, match, rep, sub =
  string.byte, string.char, string.find, string.format, string.gsub, string.match, string.rep,
  string.sub
local concat, sort = table.concat, table.sort
local floor, huge, mtype = math.floor, math.huge, math.type

local DEFAULT_MAX_DEPTH = 64

--- Sentinel returned by the decoder for JSON `null` (and accepted by the encoder).
M.null = setmetatable({}, {
  __tostring = function()
    return "null"
  end,
})

local array_mt = {}
local object_mt = {}

--- Marks a table as a JSON array so that it encodes as `[]` even when empty.
-- @param t table|nil
-- @return table
function M.array(t)
  return setmetatable(t or {}, array_mt)
end

--- Marks a table as a JSON object so that it encodes as `{}` even when empty.
-- @param t table|nil
-- @return table
function M.object(t)
  return setmetatable(t or {}, object_mt)
end

---------------------------------------------------------------------------------------------
-- Decoder
---------------------------------------------------------------------------------------------

local ParseError = {}

local function fail(message, pos)
  error(setmetatable({ message = message, pos = pos }, ParseError), 0)
end

local SIMPLE_ESCAPES = {
  ['"'] = '"',
  ["\\"] = "\\",
  ["/"] = "/",
  b = "\b",
  f = "\f",
  n = "\n",
  r = "\r",
  t = "\t",
}

local function skip_ws(s, i)
  return find(s, "[^ \t\r\n]", i) or (#s + 1)
end

local function finish_string(str, ctx, pos)
  if find(str, "[\128-\255]") and not utf8.len(str) then
    if ctx.replace_utf8 then
      return util.scrub_utf8(str)
    end
    fail("invalid UTF-8 in string", pos)
  end
  return str
end

local function parse_string(s, i, ctx)
  local pos = i + 1
  local parts, n
  while true do
    local j = find(s, '[\0-\31"\\]', pos)
    if not j then
      fail("unterminated string", i)
    end
    local c = byte(s, j)
    if c == 34 then
      if not parts then
        return finish_string(sub(s, pos, j - 1), ctx, i), j + 1
      end
      n = n + 1
      parts[n] = sub(s, pos, j - 1)
      return finish_string(concat(parts), ctx, i), j + 1
    elseif c == 92 then
      if not parts then
        parts, n = {}, 0
      end
      if j > pos then
        n = n + 1
        parts[n] = sub(s, pos, j - 1)
      end
      local e = sub(s, j + 1, j + 1)
      local simple = SIMPLE_ESCAPES[e]
      if simple then
        n = n + 1
        parts[n] = simple
        pos = j + 2
      elseif e == "u" then
        local hex = match(s, "^%x%x%x%x", j + 2)
        if not hex then
          fail("invalid \\u escape", j)
        end
        local cp = tonumber(hex, 16)
        pos = j + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          local low = match(s, "^\\u(%x%x%x%x)", pos)
          local low_cp = low and tonumber(low, 16)
          if not low_cp or low_cp < 0xDC00 or low_cp > 0xDFFF then
            fail("unpaired surrogate in \\u escape", j)
          end
          cp = 0x10000 + ((cp - 0xD800) << 10) + (low_cp - 0xDC00)
          pos = pos + 6
        elseif cp >= 0xDC00 and cp <= 0xDFFF then
          fail("unpaired surrogate in \\u escape", j)
        end
        n = n + 1
        parts[n] = utf8.char(cp)
      elseif e == "" then
        fail("unterminated string", i)
      else
        fail("invalid escape sequence", j)
      end
    else
      fail("unescaped control character in string", j)
    end
  end
end

local function parse_number(s, i)
  local _, e = find(s, "^-?0", i)
  if not e then
    _, e = find(s, "^-?[1-9]%d*", i)
  end
  if not e then
    fail("invalid number", i)
  end
  local _, frac_end = find(s, "^%.%d+", e + 1)
  if frac_end then
    e = frac_end
  elseif byte(s, e + 1) == 46 then
    fail("invalid number: digits required after the decimal point", i)
  end
  local _, exp_end = find(s, "^[eE][+-]?%d+", e + 1)
  if exp_end then
    e = exp_end
  elseif byte(s, e + 1) == 69 or byte(s, e + 1) == 101 then
    fail("invalid number: malformed exponent", i)
  end
  local nxt = byte(s, e + 1)
  if nxt and nxt >= 48 and nxt <= 57 then
    fail("invalid number: leading zeros are not allowed", i)
  end
  local value = tonumber(sub(s, i, e))
  if value ~= value or value == huge or value == -huge then
    fail("number out of range", i)
  end
  return value, e + 1
end

local decode_value

local function parse_array(s, i, depth, ctx)
  if depth > ctx.max_depth then
    fail("maximum nesting depth exceeded", i)
  end
  local result, n = {}, 0
  local pos = skip_ws(s, i + 1)
  if byte(s, pos) == 93 then
    return result, pos + 1
  end
  while true do
    local value
    value, pos = decode_value(s, pos, depth, ctx)
    n = n + 1
    result[n] = value
    pos = skip_ws(s, pos)
    local c = byte(s, pos)
    if c == 44 then
      pos = skip_ws(s, pos + 1)
    elseif c == 93 then
      return result, pos + 1
    else
      fail("expected ',' or ']'", pos)
    end
  end
end

local function parse_object(s, i, depth, ctx)
  if depth > ctx.max_depth then
    fail("maximum nesting depth exceeded", i)
  end
  local result = {}
  local pos = skip_ws(s, i + 1)
  if byte(s, pos) == 125 then
    return setmetatable(result, object_mt), pos + 1
  end
  while true do
    if byte(s, pos) ~= 34 then
      fail("expected a string key", pos)
    end
    local key, value
    key, pos = parse_string(s, pos, ctx)
    pos = skip_ws(s, pos)
    if byte(s, pos) ~= 58 then
      fail("expected ':' after object key", pos)
    end
    value, pos = decode_value(s, skip_ws(s, pos + 1), depth, ctx)
    result[key] = value
    pos = skip_ws(s, pos)
    local c = byte(s, pos)
    if c == 44 then
      pos = skip_ws(s, pos + 1)
    elseif c == 125 then
      return result, pos + 1
    else
      fail("expected ',' or '}'", pos)
    end
  end
end

local function parse_literal(s, i, word, value)
  if sub(s, i, i + #word - 1) == word then
    return value, i + #word
  end
  fail("invalid literal", i)
end

decode_value = function(s, i, depth, ctx)
  local c = byte(s, i)
  if c == 34 then
    return parse_string(s, i, ctx)
  elseif c == 123 then
    return parse_object(s, i, depth + 1, ctx)
  elseif c == 91 then
    return parse_array(s, i, depth + 1, ctx)
  elseif c == 116 then
    return parse_literal(s, i, "true", true)
  elseif c == 102 then
    return parse_literal(s, i, "false", false)
  elseif c == 110 then
    return parse_literal(s, i, "null", M.null)
  elseif c == 45 or (c and c >= 48 and c <= 57) then
    if c == 45 and byte(s, i + 1) == 73 then
      fail("Infinity is not valid JSON", i)
    end
    return parse_number(s, i)
  elseif c == 78 or c == 73 then
    fail("NaN and Infinity are not valid JSON", i)
  elseif c == nil then
    fail("unexpected end of input", i)
  end
  fail("unexpected character", i)
end

local function parse_document(s, ctx)
  local pos = skip_ws(s, 1)
  local value
  value, pos = decode_value(s, pos, 0, ctx)
  pos = skip_ws(s, pos)
  if pos <= #s then
    fail("unexpected trailing characters", pos)
  end
  return value
end

--- Decodes a JSON document.
--
-- Objects become tables with string keys, arrays become sequences, `null` becomes `json.null`.
-- Integers that fit in 64 bits decode to Lua integers, everything else to floats. Empty objects
-- are tagged so that they re-encode as `{}`.
-- @param text string
-- @param opts table|nil `{ max_depth = 64, utf8 = "strict"|"replace" }`; with "replace" invalid
--   UTF-8 inside strings is replaced by U+FFFD instead of being an error
-- @return any|nil value, or nil on error
-- @return string|nil error message with the byte position
function M.decode(text, opts)
  if type(text) ~= "string" then
    error("json.decode expects a string, got " .. type(text), 2)
  end
  local ctx = {
    max_depth = opts and opts.max_depth or DEFAULT_MAX_DEPTH,
    replace_utf8 = opts and opts.utf8 == "replace" or false,
  }
  local ok, value = pcall(parse_document, text, ctx)
  if ok then
    return value
  end
  if getmetatable(value) == ParseError then
    return nil, format("%s at position %d", value.message, value.pos)
  end
  error(value, 0)
end

---------------------------------------------------------------------------------------------
-- Encoder
---------------------------------------------------------------------------------------------

local STRING_ESCAPES = {
  ['"'] = '\\"',
  ["\\"] = "\\\\",
  ["\b"] = "\\b",
  ["\f"] = "\\f",
  ["\n"] = "\\n",
  ["\r"] = "\\r",
  ["\t"] = "\\t",
  ["\127"] = "\\u007f",
  ["<"] = "\\u003c",
  [">"] = "\\u003e",
  ["&"] = "\\u0026",
}
for b = 0, 31 do
  local c = char(b)
  STRING_ESCAPES[c] = STRING_ESCAPES[c] or format("\\u%04x", b)
end

local function line_separator(c)
  return c == "\226\128\168" and "\\u2028" or "\\u2029"
end

local function quote(s, html_safe)
  if find(s, "[\128-\255]") and not utf8.len(s) then
    s = util.scrub_utf8(s)
  end
  if html_safe then
    s = gsub(s, '[%c"\\<>&]', STRING_ESCAPES)
    s = gsub(s, "\226\128[\168\169]", line_separator)
  else
    s = gsub(s, '[%c"\\]', STRING_ESCAPES)
  end
  return '"' .. s .. '"'
end

local function encode_number(v, fail_encode)
  if mtype(v) == "integer" then
    return format("%d", v)
  end
  if v ~= v or v == huge or v == -huge then
    fail_encode("cannot encode NaN or Infinity")
  end
  if v == floor(v) and v > -1e15 and v < 1e15 then
    return format("%d", v)
  end
  local text = format("%.15g", v)
  if tonumber(text) ~= v then
    text = format("%.16g", v)
    if tonumber(text) ~= v then
      text = format("%.17g", v)
    end
  end
  if find(text, ",", 1, true) then
    text = gsub(text, ",", ".")
  end
  return text
end

local function sequence_length(t)
  local n = #t
  local count = 0
  for _ in pairs(t) do
    count = count + 1
  end
  if count ~= n then
    return nil
  end
  for i = 1, n do
    if t[i] == nil then
      return nil
    end
  end
  return n
end

local encode_value

local function is_scalar(v)
  return type(v) ~= "table" or v == M.null
end

local function encode_array(buf, t, n, ctx, level)
  if n == 0 then
    buf[#buf + 1] = "[]"
    return
  end
  local all_scalar = true
  for i = 1, n do
    if not is_scalar(t[i]) then
      all_scalar = false
      break
    end
  end
  ctx.depth = ctx.depth + 1
  if ctx.depth > ctx.max_depth then
    ctx.fail("maximum nesting depth exceeded")
  end
  if not ctx.indent then
    buf[#buf + 1] = "["
    for i = 1, n do
      if i > 1 then
        buf[#buf + 1] = ","
      end
      ctx.keys[ctx.depth] = i
      encode_value(buf, t[i], ctx, level + 1)
    end
    buf[#buf + 1] = "]"
  elseif all_scalar then
    local items, total = {}, 2
    for i = 1, n do
      ctx.keys[ctx.depth] = i
      local piece = {}
      encode_value(piece, t[i], ctx, level + 1)
      items[i] = piece[1]
      total = total + #items[i] + 2
    end
    local pad = rep(ctx.indent, level + 1)
    if total + #pad <= ctx.wrap then
      buf[#buf + 1] = "[" .. concat(items, ", ") .. "]"
    else
      local lines, current = {}, ""
      for i = 1, n do
        local piece = items[i] .. (i < n and "," or "")
        if current ~= "" and #pad + #current + 1 + #piece > ctx.wrap then
          lines[#lines + 1] = pad .. current
          current = piece
        else
          current = current == "" and piece or (current .. " " .. piece)
        end
      end
      lines[#lines + 1] = pad .. current
      buf[#buf + 1] = "[\n" .. concat(lines, "\n") .. "\n" .. rep(ctx.indent, level) .. "]"
    end
  else
    local pad = rep(ctx.indent, level + 1)
    buf[#buf + 1] = "[\n"
    for i = 1, n do
      buf[#buf + 1] = pad
      ctx.keys[ctx.depth] = i
      encode_value(buf, t[i], ctx, level + 1)
      buf[#buf + 1] = i < n and ",\n" or "\n"
    end
    buf[#buf + 1] = rep(ctx.indent, level) .. "]"
  end
  ctx.depth = ctx.depth - 1
end

local function encode_object(buf, t, ctx, level)
  local keys = {}
  for key in pairs(t) do
    if type(key) ~= "string" then
      ctx.fail("object keys must be strings (found " .. type(key) .. " key)")
    end
    keys[#keys + 1] = key
  end
  local n = #keys
  if n == 0 then
    buf[#buf + 1] = "{}"
    return
  end
  local rank = ctx.rank
  sort(keys, function(a, b)
    local ra, rb = rank[a], rank[b]
    if ra and rb then
      return ra < rb
    elseif ra then
      return true
    elseif rb then
      return false
    end
    return a < b
  end)
  ctx.depth = ctx.depth + 1
  if ctx.depth > ctx.max_depth then
    ctx.fail("maximum nesting depth exceeded")
  end
  local html_safe = ctx.html_safe
  if not ctx.indent then
    buf[#buf + 1] = "{"
    for i = 1, n do
      local key = keys[i]
      buf[#buf + 1] = (i > 1 and "," or "") .. quote(key, html_safe) .. ":"
      ctx.keys[ctx.depth] = key
      encode_value(buf, t[key], ctx, level + 1)
    end
    buf[#buf + 1] = "}"
  else
    local pad = rep(ctx.indent, level + 1)
    buf[#buf + 1] = "{\n"
    for i = 1, n do
      local key = keys[i]
      buf[#buf + 1] = pad .. quote(key, html_safe) .. ": "
      ctx.keys[ctx.depth] = key
      encode_value(buf, t[key], ctx, level + 1)
      buf[#buf + 1] = i < n and ",\n" or "\n"
    end
    buf[#buf + 1] = rep(ctx.indent, level) .. "}"
  end
  ctx.depth = ctx.depth - 1
end

encode_value = function(buf, v, ctx, level)
  local kind = type(v)
  if kind == "string" then
    buf[#buf + 1] = quote(v, ctx.html_safe)
  elseif kind == "number" then
    buf[#buf + 1] = encode_number(v, ctx.fail)
  elseif kind == "boolean" then
    buf[#buf + 1] = v and "true" or "false"
  elseif v == M.null then
    buf[#buf + 1] = "null"
  elseif kind == "table" then
    local mt = getmetatable(v)
    if mt == object_mt then
      encode_object(buf, v, ctx, level)
    elseif mt == array_mt then
      encode_array(buf, v, #v, ctx, level)
    else
      local n = sequence_length(v)
      if n then
        encode_array(buf, v, n, ctx, level)
      elseif next(v) == nil then
        buf[#buf + 1] = "[]"
      else
        encode_object(buf, v, ctx, level)
      end
    end
  else
    ctx.fail("cannot encode a value of type '" .. kind .. "'")
  end
end

--- Encodes a Lua value as JSON.
--
-- Tables are arrays when they are proper sequences (an empty table encodes as `[]` unless it was
-- created with `json.object`), otherwise objects with string keys. Object keys are sorted, with
-- the names in `key_order` first, so the output is deterministic.
-- @param value any
-- @param opts table|nil `{ indent = 2, key_order = { "schema", ... }, html_safe = true,
--   max_depth = 64, wrap = 100 }`; `indent` pretty-prints (scalar arrays stay on one line and are
--   wrapped at `wrap` columns); `html_safe` escapes `< > &` and U+2028/2029
-- @return string
-- @error for functions, userdata, NaN/Infinity, non-string object keys, sparse arrays or cycles
--   (the message names the offending path)
function M.encode(value, opts)
  opts = opts or {}
  local ctx = {
    depth = 0,
    keys = {},
    max_depth = opts.max_depth or DEFAULT_MAX_DEPTH,
    html_safe = opts.html_safe or false,
    wrap = opts.wrap or 100,
    rank = {},
  }
  if opts.indent and opts.indent > 0 then
    ctx.indent = rep(" ", opts.indent)
  end
  for i, key in ipairs(opts.key_order or {}) do
    ctx.rank[key] = i
  end
  ctx.fail = function(message)
    local path = { "$" }
    for i = 1, ctx.depth do
      local key = ctx.keys[i]
      path[#path + 1] = type(key) == "number" and ("[" .. key .. "]") or ("." .. tostring(key))
    end
    error("json.encode: " .. message .. " at " .. concat(path), 0)
  end
  local buf = {}
  encode_value(buf, value, ctx, 0)
  return concat(buf)
end

return M
