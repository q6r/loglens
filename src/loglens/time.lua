--- Calendar arithmetic and timestamp parsing without `os.time`, `os.date` or `strptime`.
--
-- Everything is computed from the proleptic Gregorian calendar (Howard Hinnant's civil-date
-- algorithms), so results do not depend on the host time zone, locale or C library. All epochs
-- are integer seconds since 1970-01-01T00:00:00Z.
-- @module loglens.time
local M = {}

local format, match = string.format, string.match
local floor, lower = math.floor, string.lower

local MONTHS = {
  jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
  jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12,
}

local DAYS_IN_MONTH = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }

local MIN_YEAR, MAX_YEAR = 1970, 9999

--- Gregorian leap-year rule.
-- @param year number
-- @return boolean
function M.is_leap(year)
  return year % 4 == 0 and (year % 100 ~= 0 or year % 400 == 0)
end

--- Number of days in a month.
-- @param year number
-- @param month number 1..12
-- @return number
function M.days_in_month(year, month)
  if month == 2 and M.is_leap(year) then
    return 29
  end
  return DAYS_IN_MONTH[month]
end

--- Days since 1970-01-01 for a civil date (valid for any proleptic Gregorian date).
-- @param year number
-- @param month number 1..12
-- @param day number 1..31
-- @return number
function M.days_from_civil(year, month, day)
  if month <= 2 then
    year = year - 1
  end
  local era = year // 400
  local year_of_era = year - era * 400
  local shifted_month = month > 2 and month - 3 or month + 9
  local day_of_year = (153 * shifted_month + 2) // 5 + day - 1
  local day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
  return era * 146097 + day_of_era - 719468
end

--- Inverse of `days_from_civil`.
-- @param days number days since 1970-01-01
-- @return number year
-- @return number month
-- @return number day
function M.civil_from_days(days)
  days = days + 719468
  local era = days // 146097
  local day_of_era = days - era * 146097
  local year_of_era = (day_of_era - day_of_era // 1460 + day_of_era // 36524
    - day_of_era // 146096) // 365
  local year = year_of_era + era * 400
  local day_of_year = day_of_era - (365 * year_of_era + year_of_era // 4 - year_of_era // 100)
  local shifted_month = (5 * day_of_year + 2) // 153
  local day_of_month = day_of_year - (153 * shifted_month + 2) // 5 + 1
  local month = shifted_month < 10 and shifted_month + 3 or shifted_month - 9
  if month <= 2 then
    year = year + 1
  end
  return year, month, day_of_month
end

--- Converts a validated civil date and clock time to a UTC epoch.
-- @param year number 1970..9999
-- @param month number 1..12
-- @param day number 1..days in month
-- @param hour number 0..23
-- @param minute number 0..59
-- @param second number 0..60 (60 is accepted for leap seconds)
-- @param offset number|nil zone offset in seconds east of UTC (`-0700` is -25200)
-- @return number|nil epoch
-- @return string|nil error message
function M.to_epoch(year, month, day, hour, minute, second, offset)
  if year < MIN_YEAR or year > MAX_YEAR then
    return nil, "year out of range"
  end
  if month < 1 or month > 12 then
    return nil, "month out of range"
  end
  if day < 1 or day > M.days_in_month(year, month) then
    return nil, "day out of range"
  end
  if hour > 23 or minute > 59 or second > 60 then
    return nil, "time of day out of range"
  end
  local days = M.days_from_civil(year, month, day)
  return days * 86400 + hour * 3600 + minute * 60 + second - (offset or 0)
end

local function parse_offset(text)
  if text == "Z" or text == "z" or match(text, "^%s*$") then
    return 0
  end
  local sign, hours, minutes = match(text, "^%s*([+-])(%d%d):?(%d?%d?)%s*$")
  if not sign then
    return nil
  end
  hours = tonumber(hours)
  minutes = minutes == "" and 0 or tonumber(minutes)
  if hours > 23 or minutes > 59 then
    return nil
  end
  local seconds = hours * 3600 + minutes * 60
  return sign == "-" and -seconds or seconds
end

--- Parses the Common Log Format timestamp `10/Oct/2000:13:55:36 -0700`.
-- A missing zone means UTC; month names are case-insensitive.
-- @param text string
-- @return number|nil epoch
-- @return string|nil error message
function M.parse_clf(text)
  local day, month_name, year, hour, minute, second, zone =
    match(text, "^(%d%d?)/(%a%a%a)/(%d%d%d%d):(%d%d):(%d%d):(%d%d)(.*)$")
  if not day then
    return nil, "malformed timestamp"
  end
  local month = MONTHS[lower(month_name)]
  if not month then
    return nil, "unknown month name"
  end
  local offset = parse_offset(zone)
  if not offset then
    return nil, "malformed time zone"
  end
  return M.to_epoch(tonumber(year), month, tonumber(day), tonumber(hour), tonumber(minute),
    tonumber(second), offset)
end

--- Parses ISO 8601 / RFC 3339 timestamps: `2026-11-10`, `2026-11-10T14:03`, `2026-11-10 14:03:09`,
-- `2026-11-10T14:03:09.123Z`, `2026-11-10T14:03:09+02:00`. Fractions are ignored; a missing zone
-- means UTC.
-- @param text string
-- @return number|nil epoch
-- @return string|nil error message
function M.parse_iso(text)
  local year, month, day, rest = match(text, "^(%d%d%d%d)-(%d%d)-(%d%d)(.*)$")
  if not year then
    return nil, "malformed timestamp"
  end
  local hour, minute, second = 0, 0, 0
  local offset = 0
  if rest ~= "" then
    local h, m, tail = match(rest, "^[Tt ](%d%d):(%d%d)(.*)$")
    if not h then
      return nil, "malformed timestamp"
    end
    hour, minute = tonumber(h), tonumber(m)
    local s, after_seconds = match(tail, "^:(%d%d)(.*)$")
    if s then
      second, tail = tonumber(s), after_seconds
    end
    local after_fraction = match(tail, "^[.,]%d+(.*)$")
    if after_fraction then
      tail = after_fraction
    end
    offset = parse_offset(tail)
    if not offset then
      return nil, "malformed time zone"
    end
  end
  return M.to_epoch(tonumber(year), tonumber(month), tonumber(day), hour, minute, second, offset)
end

--- Interprets a number as an epoch, guessing the unit from its magnitude: seconds below 1e11,
-- milliseconds below 1e14, microseconds below 1e17, otherwise nanoseconds.
-- @param value number
-- @return number|nil epoch in whole seconds
-- @return string|nil error message
function M.from_number(value)
  if value ~= value or value < 0 or value == math.huge then
    return nil, "timestamp out of range"
  end
  if value >= 1e17 then
    value = value / 1e9
  elseif value >= 1e14 then
    value = value / 1e6
  elseif value >= 1e11 then
    value = value / 1e3
  end
  if value < 1 or value > 253402300799 then
    return nil, "timestamp out of range"
  end
  return floor(value)
end

--- Parses a timestamp found in a structured log: a number (epoch), a numeric string, an ISO 8601
-- string or a Common Log Format string.
-- @param value number|string
-- @return number|nil epoch
-- @return string|nil error message
function M.parse_value(value)
  if type(value) == "number" then
    return M.from_number(value)
  end
  if type(value) ~= "string" then
    return nil, "missing timestamp"
  end
  if match(value, "^%d+%.?%d*$") then
    return M.from_number(tonumber(value))
  end
  if match(value, "^%d%d?/%a%a%a/") then
    return M.parse_clf(value)
  end
  return M.parse_iso(value)
end

local function split_epoch(epoch)
  epoch = floor(epoch)
  local days = epoch // 86400
  local seconds = epoch - days * 86400
  local year, month, day = M.civil_from_days(days)
  return year, month, day, seconds // 3600, (seconds % 3600) // 60, seconds % 60
end

--- Formats an epoch as `2026-11-10T14:03:09Z`.
-- @param epoch number
-- @return string
function M.format_iso(epoch)
  local year, month, day, hour, minute, second = split_epoch(epoch)
  return format("%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second)
end

--- Formats an epoch as `2026-11-10`.
-- @param epoch number
-- @return string
function M.format_date(epoch)
  local year, month, day = split_epoch(epoch)
  return format("%04d-%02d-%02d", year, month, day)
end

--- Formats an epoch as `14:03`.
-- @param epoch number
-- @return string
function M.format_clock(epoch)
  local _, _, _, hour, minute = split_epoch(epoch)
  return format("%02d:%02d", hour, minute)
end

--- Formats an epoch as `2026-11-10 14:03`.
-- @param epoch number
-- @return string
function M.format_datetime(epoch)
  local year, month, day, hour, minute = split_epoch(epoch)
  return format("%04d-%02d-%02d %02d:%02d", year, month, day, hour, minute)
end

return M
