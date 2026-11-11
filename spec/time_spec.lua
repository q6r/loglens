local t = require("spec.support")
local time = require("loglens.time")

t.describe("time.is_leap / days_in_month", function()
  t.it("applies the Gregorian rule", function()
    t.is_true(time.is_leap(2000))
    t.is_true(time.is_leap(2024))
    t.is_true(time.is_leap(2028))
    t.is_false(time.is_leap(1900))
    t.is_false(time.is_leap(2100))
    t.is_false(time.is_leap(2023))
    t.is_false(time.is_leap(2026))
    t.eq(time.days_in_month(2024, 2), 29)
    t.eq(time.days_in_month(2100, 2), 28)
    t.eq(time.days_in_month(2026, 4), 30)
    t.eq(time.days_in_month(2026, 12), 31)
  end)
end)

t.describe("time.days_from_civil / civil_from_days", function()
  t.it("matches well-known epochs", function()
    t.eq(time.days_from_civil(1970, 1, 1), 0)
    t.eq(time.days_from_civil(2000, 1, 1) * 86400, 946684800)
    t.eq(time.days_from_civil(2001, 9, 9) * 86400 + 6400, 1000000000)
    t.eq(time.days_from_civil(2024, 1, 1) * 86400, 1704067200)
    t.eq(time.days_from_civil(2100, 1, 1) * 86400, 4102444800)
    t.eq(time.days_from_civil(1969, 12, 31), -1)
  end)

  t.it("agrees with a day-by-day walk across 165 years (leap years, 2100, 2000)", function()
    local year, month, day = 1970, 1, 1
    for days = 0, 60300 do
      if days % 7 == 0 or day == 1 or day >= 28 then
        t.eq(time.days_from_civil(year, month, day), days)
        local y, m, d = time.civil_from_days(days)
        t.eq({ y, m, d }, { year, month, day })
      end
      day = day + 1
      if day > time.days_in_month(year, month) then
        day, month = 1, month + 1
        if month > 12 then
          month, year = 1, year + 1
        end
      end
    end
    t.eq(year, 2135)
  end)

  t.it("handles dates before 1970", function()
    t.eq({ time.civil_from_days(-1) }, { 1969, 12, 31 })
    t.eq({ time.civil_from_days(-719468) }, { 0, 3, 1 })
    t.eq({ time.civil_from_days(time.days_from_civil(1900, 2, 28) + 1) }, { 1900, 3, 1 })
  end)
end)

t.describe("time.parse_clf", function()
  t.it("parses the canonical Apache example in its own zone", function()
    t.eq(time.parse_clf("10/Oct/2000:13:55:36 -0700"), 971211336)
    t.eq(time.format_iso(971211336), "2000-10-10T20:55:36Z")
  end)

  t.it("honours positive, negative, half-hour and zero offsets", function()
    local utc = time.parse_clf("10/Nov/2026:12:00:00 +0000")
    t.eq(time.parse_clf("10/Nov/2026:14:00:00 +0200"), utc)
    t.eq(time.parse_clf("10/Nov/2026:07:00:00 -0500"), utc)
    t.eq(time.parse_clf("10/Nov/2026:17:30:00 +0530"), utc)
    t.eq(time.parse_clf("10/Nov/2026:08:15:00 -0345"), utc)
    t.eq(time.parse_clf("10/Nov/2026:12:00:00 +00:00"), utc)
    t.eq(time.parse_clf("10/Nov/2026:12:00:00"), utc, "missing zone means UTC")
    t.eq(time.parse_clf("10/Nov/2026:12:00:00 "), utc)
  end)

  t.it("crosses day, month and year boundaries through the zone", function()
    t.eq(time.format_iso(time.parse_clf("31/Dec/2025:23:30:00 -0100")), "2026-01-01T00:30:00Z")
    t.eq(time.format_iso(time.parse_clf("01/Jan/2026:00:30:00 +0100")), "2025-12-31T23:30:00Z")
    t.eq(time.format_iso(time.parse_clf("01/Mar/2024:00:00:00 +0100")), "2024-02-29T23:00:00Z")
    t.eq(time.format_iso(time.parse_clf("01/Mar/2023:00:00:00 +0100")), "2023-02-28T23:00:00Z")
  end)

  t.it("understands leap days and rejects impossible ones", function()
    t.eq(time.parse_clf("29/Feb/2000:00:00:00 +0000"), 951782400)
    t.eq(time.parse_clf("29/Feb/2024:00:00:00 +0000"), 1709164800)
    t.is_nil(time.parse_clf("29/Feb/2023:00:00:00 +0000"))
    t.is_nil(time.parse_clf("29/Feb/2100:00:00:00 +0000"))
    t.is_nil(time.parse_clf("31/Apr/2026:00:00:00 +0000"))
    t.is_nil(time.parse_clf("00/Jan/2026:00:00:00 +0000"))
    t.eq(time.parse_clf("29/Feb/2024:23:59:59 +0000") + 1, time.parse_clf("01/Mar/2024:00:00:00 +0000"))
  end)

  t.it("works beyond 2038", function()
    t.eq(time.parse_clf("19/Jan/2038:03:14:08 +0000"), 2147483648)
    t.eq(time.parse_clf("01/Jan/2100:00:00:00 +0000"), 4102444800)
  end)

  t.it("accepts any month-name case and a leap second", function()
    local base = time.parse_clf("10/Nov/2026:12:00:00 +0000")
    t.eq(time.parse_clf("10/NOV/2026:12:00:00 +0000"), base)
    t.eq(time.parse_clf("10/nov/2026:12:00:00 +0000"), base)
    t.eq(time.parse_clf("10/Nov/2026:11:59:60 +0000"), base)
    t.eq(time.parse_clf("1/Nov/2026:00:00:00 +0000"), time.parse_clf("01/Nov/2026:00:00:00 +0000"))
  end)

  t.it("rejects malformed timestamps with a reason", function()
    for _, bad in ipairs({
      "",
      "garbage",
      "10/Foo/2026:12:00:00 +0000",
      "10/Nov/26:12:00:00 +0000",
      "10/Nov/2026 12:00:00 +0000",
      "10/Nov/2026:24:00:00 +0000",
      "10/Nov/2026:12:60:00 +0000",
      "10/Nov/2026:12:00:61 +0000",
      "10/Nov/2026:12:00:00 +2400",
      "10/Nov/2026:12:00:00 +0060",
      "10/Nov/2026:12:00:00 UTC",
      "10/Nov/1969:12:00:00 +0000",
      "10/Nov/2026:12:00:00 +0000 extra",
    }) do
      local value, err = time.parse_clf(bad)
      t.is_nil(value, "should reject " .. bad)
      t.ok(err, "reason for " .. bad)
    end
  end)
end)

t.describe("time.parse_iso", function()
  t.it("parses the common shapes", function()
    local utc = 1700000000
    t.eq(time.parse_iso("2023-11-14T22:13:20Z"), utc)
    t.eq(time.parse_iso("2023-11-14T22:13:20"), utc)
    t.eq(time.parse_iso("2023-11-14 22:13:20"), utc)
    t.eq(time.parse_iso("2023-11-14t22:13:20z"), utc)
    t.eq(time.parse_iso("2023-11-14T22:13:20.987654Z"), utc)
    t.eq(time.parse_iso("2023-11-14T23:13:20+01:00"), utc)
    t.eq(time.parse_iso("2023-11-14T17:13:20-0500"), utc)
    t.eq(time.parse_iso("2023-11-14T22:13Z"), utc - 20)
    t.eq(time.parse_iso("2023-11-14"), 1699920000)
  end)

  t.it("rejects invalid values", function()
    for _, bad in ipairs({ "", "2023-11-14T25:00:00Z", "2023-13-01", "2023-02-30", "2023-11-14T22",
      "2023-11-14T22:13:20+25:00", "yesterday", "14/11/2023", "2023-11-14T22:13:20 PST" }) do
      t.is_nil(time.parse_iso(bad), "should reject " .. bad)
    end
  end)
end)

t.describe("time.parse_value", function()
  t.it("guesses epoch units", function()
    t.eq(time.parse_value(1700000000), 1700000000)
    t.eq(time.parse_value(1700000000.75), 1700000000)
    t.eq(time.parse_value(1700000000123), 1700000000)
    t.eq(time.parse_value(1700000000123456), 1700000000)
    t.eq(time.parse_value(1700000000123456789), 1700000000)
    t.eq(time.parse_value("1700000000.5"), 1700000000)
  end)

  t.it("dispatches on string shape", function()
    t.eq(time.parse_value("2023-11-14T22:13:20Z"), 1700000000)
    t.eq(time.parse_value("14/Nov/2023:22:13:20 +0000"), 1700000000)
  end)

  t.it("rejects nonsense", function()
    t.is_nil(time.parse_value(-5))
    t.is_nil(time.parse_value(0))
    t.is_nil(time.parse_value(0 / 0))
    t.is_nil(time.parse_value(math.huge))
    t.is_nil(time.parse_value(true))
    t.is_nil(time.parse_value(nil))
    t.is_nil(time.parse_value("soon"))
    t.is_nil(time.parse_value({}))
  end)
end)

t.describe("time formatting", function()
  t.it("formats epochs", function()
    t.eq(time.format_iso(0), "1970-01-01T00:00:00Z")
    t.eq(time.format_iso(1234567890), "2009-02-13T23:31:30Z")
    t.eq(time.format_iso(2147483647), "2038-01-19T03:14:07Z")
    t.eq(time.format_iso(1709164800), "2024-02-29T00:00:00Z")
    t.eq(time.format_iso(1709164800.9), "2024-02-29T00:00:00Z")
    t.eq(time.format_date(1700000000), "2023-11-14")
    t.eq(time.format_clock(1700000000), "22:13")
    t.eq(time.format_datetime(1700000000), "2023-11-14 22:13")
  end)

  t.it("round-trips through parse_iso for many instants", function()
    local epoch = 0
    for _ = 1, 4000 do
      epoch = epoch + 1234567
      t.eq(time.parse_iso(time.format_iso(epoch)), epoch)
    end
  end)
end)
