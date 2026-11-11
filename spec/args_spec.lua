local t = require("spec.support")
local args = require("loglens.args")

local OPTIONS = {
  { name = "format", short = "f", value = "NAME", choices = { "auto", "combined", "json" }, help = "log format" },
  { name = "top", short = "n", value = "N", kind = "integer", help = "rows" },
  { name = "interval", value = "SECONDS", kind = "number", help = "seconds" },
  { name = "no-color", help = "plain output" },
  { name = "verbose", short = "v", help = "more output" },
}

t.describe("args.parse", function()
  t.it("splits options and positional arguments in any order", function()
    local parsed = args.parse({ "access.log", "--top", "5", "other.log", "-f", "json" }, OPTIONS)
    t.eq(parsed.args, { "access.log", "other.log" })
    t.eq(parsed.options, { top = 5, format = "json" })
  end)

  t.it("accepts --name=value, -nVALUE and flags", function()
    local parsed = args.parse({ "--top=7", "-f", "combined", "--no-color", "-v" }, OPTIONS)
    t.eq(parsed.options, { top = 7, format = "combined", no_color = true, verbose = true })
    t.eq(args.parse({ "-n12" }, OPTIONS).options.top, 12)
  end)

  t.it("converts numbers and keeps integers integral", function()
    local parsed = args.parse({ "--interval", "0.25", "--top", "10.0" }, OPTIONS)
    t.eq(parsed.options.interval, 0.25)
    t.eq(math.type(parsed.options.top), "integer")
  end)

  t.it("treats '-' as a file name and '--' as the end of the options", function()
    t.eq(args.parse({ "-" }, OPTIONS).args, { "-" })
    local parsed = args.parse({ "--top", "1", "--", "--top", "-v" }, OPTIONS)
    t.eq(parsed.args, { "--top", "-v" })
    t.eq(parsed.options, { top = 1 })
  end)

  t.it("lets the last occurrence win", function()
    t.eq(args.parse({ "-n", "1", "-n", "2" }, OPTIONS).options.top, 2)
  end)

  t.it("rejects unknown options and suggests the closest one", function()
    local parsed, err = args.parse({ "--formt", "json" }, OPTIONS)
    t.is_nil(parsed)
    t.contains(err, "unknown option '--formt'")
    t.contains(err, "Did you mean '--format'?")
    local _, other = args.parse({ "-x" }, OPTIONS)
    t.contains(other, "unknown option '-x'")
    t.not_contains(other, "Did you mean")
  end)

  t.it("rejects missing, surplus and invalid values", function()
    local _, missing = args.parse({ "--top" }, OPTIONS)
    t.contains(missing, "needs a value")
    local _, short_missing = args.parse({ "-n" }, OPTIONS)
    t.contains(short_missing, "needs a value")
    local _, surplus = args.parse({ "--verbose=1" }, OPTIONS)
    t.contains(surplus, "does not take a value")
    local _, combined = args.parse({ "-vn", "3" }, OPTIONS)
    t.contains(combined, "does not take a value")
    local _, word = args.parse({ "--top", "many" }, OPTIONS)
    t.contains(word, "invalid value 'many' for --top")
    local _, fraction = args.parse({ "--top", "2.5" }, OPTIONS)
    t.contains(fraction, "whole number")
    local _, nan = args.parse({ "--interval", "nan" }, OPTIONS)
    t.contains(nan, "expected a number")
    local _, choice = args.parse({ "--format", "xml" }, OPTIONS)
    t.contains(choice, "expected auto, combined, json")
  end)

  t.it("takes the next word as the value even when it starts with a dash", function()
    t.eq(args.parse({ "--interval", "-1" }, OPTIONS).options.interval, -1)
  end)

  t.it("never fails on arbitrary input (fuzz)", function()
    local alphabet = { "-", "--", "-n", "--top", "=", "x", "5", "", "--no-color", "-f", "json", "--", "é" }
    local state = 12345
    for _ = 1, 300 do
      local argv = {}
      for i = 1, state % 6 do
        state = (state * 1103515245 + 12345) % 2147483648
        argv[i] = alphabet[state % #alphabet + 1]
      end
      state = (state * 1103515245 + 12345) % 2147483648
      local parsed, err = args.parse(argv, OPTIONS)
      t.ok(parsed ~= nil or type(err) == "string")
    end
  end)
end)

t.describe("args.help_lines", function()
  t.it("aligns the descriptions", function()
    local lines = args.help_lines(OPTIONS)
    t.eq(#lines, #OPTIONS)
    t.eq(lines[1], "  -f, --format NAME" .. string.rep(" ", 7) .. "log format")
    t.eq(lines[4], "      --no-color" .. string.rep(" ", 10) .. "plain output")
    local column = lines[1]:find("log format", 1, true)
    for i, line in ipairs(lines) do
      t.eq(line:find(OPTIONS[i].help, 1, true), column, "description column of line " .. i)
    end
  end)
end)
