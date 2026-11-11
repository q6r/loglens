--- Small, dependency-free helpers shared by the loglens modules.
--
-- Everything here is pure: no I/O, no global state.
-- @module loglens.util
local M = {}

local byte, char, find, format, gsub, lower, match, rep, sub =
  string.byte, string.char, string.find, string.format, string.gsub, string.lower, string.match,
  string.rep, string.sub
local concat, sort = table.concat, table.sort
local abs, floor, max = math.abs, math.floor, math.max

M.ELLIPSIS = "\u{2026}"

--- Removes leading and trailing whitespace (linear time, safe for very long strings).
-- @param s string
-- @return string
function M.trim(s)
  local first = find(s, "%S")
  if not first then
    return ""
  end
  local last = #s
  while last > first do
    local b = byte(s, last)
    if b == 32 or (b >= 9 and b <= 13) then
      last = last - 1
    else
      break
    end
  end
  return sub(s, first, last)
end

--- Decodes `%XX` escapes (malformed escapes are left untouched, `+` is not translated).
-- @param s string
-- @return string
function M.percent_decode(s)
  if not find(s, "%", 1, true) then
    return s
  end
  return (gsub(s, "%%(%x%x)", function(hex)
    return char(tonumber(hex, 16))
  end))
end

--- Replaces invalid UTF-8 sequences with U+FFFD so the result is always valid UTF-8.
-- @param s string
-- @param replacement string|nil (default U+FFFD)
-- @return string
function M.scrub_utf8(s, replacement)
  if utf8.len(s) then
    return s
  end
  replacement = replacement or "\u{FFFD}"
  local parts, pos = {}, 1
  while pos <= #s do
    local len, bad = utf8.len(s, pos)
    if len then
      parts[#parts + 1] = sub(s, pos)
      break
    end
    parts[#parts + 1] = sub(s, pos, bad - 1)
    parts[#parts + 1] = replacement
    pos = bad + 1
  end
  return concat(parts)
end

-- Terminal column width of one code point (0 for combining/zero-width, 2 for wide CJK/emoji).
local function codepoint_width(cp)
  if cp < 0x300 then
    return 1
  end
  if (cp >= 0x300 and cp <= 0x36F) or (cp >= 0x200B and cp <= 0x200F) or cp == 0xFEFF
      or (cp >= 0xFE00 and cp <= 0xFE0F) then
    return 0
  end
  if (cp >= 0x1100 and cp <= 0x115F) or (cp >= 0x2E80 and cp <= 0xA4CF)
      or (cp >= 0xAC00 and cp <= 0xD7A3) or (cp >= 0xF900 and cp <= 0xFAFF)
      or (cp >= 0xFE30 and cp <= 0xFE6F) or (cp >= 0xFF00 and cp <= 0xFF60)
      or (cp >= 0xFFE0 and cp <= 0xFFE6) or (cp >= 0x1F300 and cp <= 0x1F64F)
      or (cp >= 0x1F900 and cp <= 0x1F9FF) or (cp >= 0x20000 and cp <= 0x3FFFD) then
    return 2
  end
  return 1
end

--- Number of terminal columns used by a string (UTF-8 aware, ANSI escapes are NOT stripped).
-- @param s string
-- @return number
function M.display_width(s)
  if not find(s, "[\128-\255]") then
    return #s
  end
  if not utf8.len(s) then
    return #s
  end
  local width = 0
  for _, cp in utf8.codes(s) do
    width = width + codepoint_width(cp)
  end
  return width
end

--- Removes ANSI CSI escape sequences (colours, cursor movement).
-- @param s string
-- @return string
function M.strip_ansi(s)
  return (gsub(s, "\27%[[%d;?]*%a", ""))
end

--- Display width ignoring ANSI escape sequences.
-- @param s string
-- @return number
function M.visible_width(s)
  if find(s, "\27", 1, true) then
    s = M.strip_ansi(s)
  end
  return M.display_width(s)
end

--- Truncates to at most `cols` terminal columns, appending `ellipsis` when something was cut.
-- @param s string plain text (no ANSI escapes)
-- @param cols number
-- @param ellipsis string|nil (default U+2026)
-- @return string
function M.truncate(s, cols, ellipsis)
  ellipsis = ellipsis or M.ELLIPSIS
  if M.display_width(s) <= cols then
    return s
  end
  local budget = cols - M.display_width(ellipsis)
  if budget < 0 then
    return ""
  end
  if not find(s, "[\128-\255]") or not utf8.len(s) then
    return sub(s, 1, budget) .. ellipsis
  end
  local width, cut = 0, 1
  for pos, cp in utf8.codes(s) do
    local w = codepoint_width(cp)
    if width + w > budget then
      break
    end
    width = width + w
    cut = pos + #utf8.char(cp)
  end
  return sub(s, 1, cut - 1) .. ellipsis
end

--- Right-pads with spaces to `cols` columns (ANSI aware); never truncates.
function M.pad_right(s, cols)
  local gap = cols - M.visible_width(s)
  if gap <= 0 then
    return s
  end
  return s .. rep(" ", gap)
end

--- Left-pads with spaces to `cols` columns (ANSI aware); never truncates.
function M.pad_left(s, cols)
  local gap = cols - M.visible_width(s)
  if gap <= 0 then
    return s
  end
  return rep(" ", gap) .. s
end

--- Word-wraps plain text into lines of at most `cols` terminal columns. Runs of whitespace
-- collapse to one space and a word wider than a line is truncated.
-- @param text string plain text (no ANSI escapes)
-- @param cols number
-- @return string[]
function M.wrap(text, cols)
  local lines, words, used = {}, {}, 0
  for word in text:gmatch("%S+") do
    word = M.truncate(word, cols)
    local width = M.display_width(word)
    if used > 0 and used + 1 + width > cols then
      lines[#lines + 1] = concat(words, " ")
      words, used = {}, 0
    end
    words[#words + 1] = word
    used = used + width + (used > 0 and 1 or 0)
  end
  if #words > 0 then
    lines[#lines + 1] = concat(words, " ")
  end
  return lines
end

-- Escape table for ASCII bytes: control bytes become \xNN, "active" characters become %XX.
local ESCAPES = {}
for b = 0, 31 do
  ESCAPES[b] = format("\\x%02X", b)
end
ESCAPES[127] = "\\x7F"
for ch in ("<>\"'`${}\\"):gmatch(".") do
  ESCAPES[byte(ch)] = format("%%%02X", byte(ch))
end

local UNSAFE = "[%c<>\"'`$%{%}\\\128-\255]"

-- Code points that are invisible or can reorder/hide text in a terminal or browser.
local function is_dangerous_codepoint(cp)
  return (cp >= 0x80 and cp <= 0x9F) or cp == 0x061C or cp == 0x180E
    or (cp >= 0x200B and cp <= 0x200F) or (cp >= 0x2028 and cp <= 0x202E)
    or (cp >= 0x2060 and cp <= 0x206F) or cp == 0xFEFF or (cp >= 0xFFF9 and cp <= 0xFFFC)
    or (cp >= 0xE0001 and cp <= 0xE007F)
end

--- Makes untrusted log text safe to print: control bytes, invalid UTF-8 and invisible/bidi code
-- points are written as `\xNN` / `\uXXXX` / `\UXXXXXXXX` (never with braces), and characters that
-- can turn a payload into live markup or shell syntax (`< > " ' ` $ { } \`) are percent-encoded.
-- The result is truncated to `max_cols` terminal columns.
-- @param s string untrusted text
-- @param max_cols number|nil column budget (nil = unlimited)
-- @param ellipsis string|nil marker for truncation (default U+2026)
-- @return string
function M.defang(s, max_cols, ellipsis)
  s = tostring(s)
  ellipsis = ellipsis or M.ELLIPSIS
  local clipped = false
  if max_cols and #s > max_cols * 4 + 16 then
    s = sub(s, 1, max_cols * 4 + 16)
    clipped = true
  end
  if not find(s, UNSAFE) then
    if not max_cols or (#s <= max_cols and not clipped) then
      return s
    end
    return sub(s, 1, max(0, max_cols - M.display_width(ellipsis))) .. ellipsis
  end

  -- Output is assembled from pieces: plain ASCII runs (`runs[i]`, may be cut anywhere) and
  -- atomic escapes or characters.
  local texts, widths, runs, count = {}, {}, {}, 0
  local pos, len = 1, #s
  while pos <= len do
    local hit = find(s, UNSAFE, pos)
    if not hit then
      count = count + 1
      texts[count], widths[count], runs[count] = sub(s, pos), len - pos + 1, true
      break
    end
    if hit > pos then
      count = count + 1
      texts[count], widths[count], runs[count] = sub(s, pos, hit - 1), hit - pos, true
    end
    local b = byte(s, hit)
    count = count + 1
    pos = hit + 1
    if b < 128 then
      texts[count] = ESCAPES[b]
      widths[count] = #texts[count]
    elseif utf8.len(s, hit, hit) == 1 then
      local cp = utf8.codepoint(s, hit)
      local encoded = utf8.char(cp)
      if is_dangerous_codepoint(cp) then
        texts[count] = cp <= 0xFFFF and format("\\u%04X", cp) or format("\\U%08X", cp)
        widths[count] = #texts[count]
      else
        texts[count] = encoded
        widths[count] = codepoint_width(cp)
      end
      pos = hit + #encoded
    else
      texts[count] = format("\\x%02X", b)
      widths[count] = 4
    end
  end

  if not max_cols then
    return concat(texts)
  end
  local total = 0
  for i = 1, count do
    total = total + widths[i]
  end
  if total <= max_cols and not clipped then
    return concat(texts)
  end
  local budget = max(0, max_cols - M.display_width(ellipsis))
  local used, kept, partial = 0, 0, ""
  for i = 1, count do
    if used + widths[i] > budget then
      if runs[i] and budget > used then
        partial = sub(texts[i], 1, budget - used)
      end
      break
    end
    used = used + widths[i]
    kept = i
  end
  return concat(texts, "", 1, kept) .. partial .. ellipsis
end

--- Rounds to `digits` decimals (half up). Returns an integer when `digits` is 0 or nil.
-- @param x number
-- @param digits number|nil
-- @return number
function M.round(x, digits)
  if not digits or digits == 0 then
    return floor(x + 0.5)
  end
  local scale = 10 ^ digits
  return floor(x * scale + 0.5) / scale
end

--- Formats an integer-valued number with thousands separators ("1,234,567").
-- @param n number
-- @return string
function M.fmt_int(n)
  local text = format("%d", M.round(n))
  local left, digits, right = match(text, "^([^%d]*%d)(%d*)(.-)$")
  return left .. gsub(digits:reverse(), "(%d%d%d)", "%1,"):reverse() .. right
end

--- Compact count: full below 10,000, then 12.9K / 4.2M / 1.1B.
-- @param n number
-- @return string
function M.fmt_compact(n)
  if n < 10000 then
    return M.fmt_int(n)
  end
  local suffixes = { "K", "M", "B" }
  local index = n >= 1e9 and 3 or (n >= 1e6 and 2 or 1)
  local value = n / 10 ^ (3 * index)
  if value >= 999.95 and index < #suffixes then
    index, value = index + 1, value / 1000
  end
  return (gsub(format("%.1f", value), "%.0$", "")) .. suffixes[index]
end

--- Human readable byte count (1024 base): "512 B", "1.5 KiB", "12.3 MiB".
-- @param n number
-- @return string
function M.fmt_bytes(n)
  if n < 1024 then
    return format("%d B", M.round(n))
  end
  local units = { "KiB", "MiB", "GiB", "TiB", "PiB" }
  local value = n / 1024
  local index = 1
  while value >= 1023.95 and index < #units do
    value = value / 1024
    index = index + 1
  end
  return format("%.1f %s", value, units[index])
end

--- Human readable duration from milliseconds: "0.4 ms", "820 ms", "3.2 s", "2m 05s", "1h 03m".
-- @param ms number
-- @return string
function M.fmt_duration_ms(ms)
  if ms < 9.95 then
    return format("%.1f ms", ms)
  elseif ms < 999.5 then
    return format("%d ms", M.round(ms))
  elseif ms < 59950 then
    return format("%.1f s", ms / 1000)
  end
  local seconds = M.round(ms / 1000)
  if seconds < 3600 then
    return format("%dm %02ds", seconds // 60, seconds % 60)
  end
  return format("%dh %02dm", seconds // 3600, (seconds % 3600) // 60)
end

--- Formats a ratio as a percentage: 0.1234 -> "12.3%".
-- @param ratio number
-- @param digits number|nil decimals (default 1)
-- @return string
function M.fmt_pct(ratio, digits)
  return format("%." .. (digits or 1) .. "f%%", ratio * 100)
end

--- Levenshtein edit distance between two strings (byte based).
-- @param a string
-- @param b string
-- @return number
function M.edit_distance(a, b)
  if a == b then
    return 0
  end
  local la, lb = #a, #b
  if la == 0 then
    return lb
  end
  if lb == 0 then
    return la
  end
  local previous, current = {}, {}
  for j = 0, lb do
    previous[j] = j
  end
  for i = 1, la do
    current[0] = i
    local ca = byte(a, i)
    for j = 1, lb do
      local cost = (ca == byte(b, j)) and 0 or 1
      current[j] = math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
    end
    previous, current = current, previous
  end
  return previous[lb]
end

--- Suggests the closest candidate to a mistyped word, or nil when nothing is close.
-- @param word string
-- @param candidates string[]
-- @return string|nil
function M.suggest(word, candidates)
  local best, best_distance = nil, math.huge
  local limit = max(2, #word // 3)
  for _, candidate in ipairs(candidates) do
    local distance = M.edit_distance(lower(word), lower(candidate))
    if distance < best_distance then
      best, best_distance = candidate, distance
    end
  end
  if best and best_distance <= limit then
    return best
  end
  return nil
end

--- Extracts the lower-cased host of an absolute URL (no userinfo, no port), or nil.
-- @param url string
-- @return string|nil
function M.url_host(url)
  local authority = match(url, "^%a[%w+.%-]*://([^/?#]*)")
  if not authority then
    return nil
  end
  authority = match(authority, "([^@]*)$")
  local host = match(authority, "^%[([^%]]+)%]") or match(authority, "^([^:]+)")
  if not host or host == "" then
    return nil
  end
  return lower(host)
end

local function median_of_sorted(sorted)
  local n = #sorted
  if n == 0 then
    return 0
  end
  if n % 2 == 1 then
    return sorted[(n + 1) // 2]
  end
  return (sorted[n // 2] + sorted[n // 2 + 1]) / 2
end

--- Median of an array of numbers (the input is not modified).
-- @param values number[]
-- @return number 0 for an empty array
function M.median(values)
  local sorted = {}
  for i = 1, #values do
    sorted[i] = values[i]
  end
  sort(sorted)
  return median_of_sorted(sorted)
end

--- Robust centre and scale for outlier detection (modified z-score of Iglewicz and Hoaglin).
-- `z = (x - median) / scale`. The scale is 1.4826 * MAD, falling back to 1.2533 * mean absolute
-- deviation when more than half of the values are identical (MAD = 0).
-- @param values number[]
-- @return number median
-- @return number scale (0 when all values are identical)
function M.robust_scale(values)
  local n = #values
  if n == 0 then
    return 0, 0
  end
  local centre = M.median(values)
  local deviations, sum = {}, 0
  for i = 1, n do
    deviations[i] = abs(values[i] - centre)
    sum = sum + deviations[i]
  end
  sort(deviations)
  local mad = median_of_sorted(deviations)
  if mad > 0 then
    return centre, 1.4826 * mad
  end
  if sum > 0 then
    return centre, 1.253314 * (sum / n)
  end
  return centre, 0
end

return M
