local t = require("spec.support")
local cli = require("loglens.cli")
local fakes = require("spec.fakes")
local json = require("loglens.json")
local loggen = require("tools.loggen")
local summary_module = require("loglens.summary")
local util = require("loglens.util")

-- ~940 lines: regular traffic plus every scripted incident, so there are findings of every severity.
local LOG_TEXT = table.concat(loggen.lines({ seed = 5, count = 120 }), "\n") .. "\n"

local function run(argv, opts)
  opts = opts or {}
  opts.files = opts.files or { ["access.log"] = LOG_TEXT }
  local env, probe = fakes.env(opts)
  local code = cli.main(argv, env)
  return code, probe.stdout(), probe.stderr(), probe
end

local function decoded(text)
  local value, err = json.decode(text)
  t.ok(value, "output is not JSON: " .. tostring(err))
  return value
end

t.describe("cli help and version", function()
  t.it("prints the usage to stderr and fails when called without arguments", function()
    local code, out, err = run({})
    t.eq(code, 2)
    t.eq(out, "")
    t.contains(err, "Usage:")
    t.contains(err, "loglens json")
  end)

  t.it("shows help for the tool and for each command", function()
    local code, out = run({ "--help" })
    t.eq(code, 0)
    t.contains(out, "loglens watch [options] <file|->")
    for _, command in ipairs({ "report", "json", "html", "watch" }) do
      local status, help = run({ command, "--help" })
      t.eq(status, 0)
      t.contains(help, "Usage: loglens")
      t.contains(help, "--format NAME")
    end
    t.contains(select(2, run({ "json", "-h" })), "--compact")
    t.contains(select(2, run({ "help", "html" })), "Usage: loglens html")
    t.contains(select(2, run({ "help" })), "Exit status")
  end)

  t.it("prints the version", function()
    local code, out = run({ "version" })
    t.eq(code, 0)
    t.eq(out, "loglens " .. require("loglens.version") .. " (" .. _VERSION .. ")\n")
    t.eq(select(2, run({ "--version" })), out)
    t.eq(select(2, run({ "-V" })), out)
  end)

  t.it("lists the supported formats with an example each", function()
    local code, out = run({ "formats" })
    t.eq(code, 0)
    for _, name in ipairs({ "combined", "common", "json", "caddy" }) do
      t.matches(out, "\n?" .. name .. "\n  ")
    end
    t.contains(out, "e.g. 203.0.113.9")
  end)
end)

t.describe("cli usage errors", function()
  t.it("rejects unknown options with a suggestion", function()
    local code, _, err = run({ "report", "--formt", "json", "access.log" })
    t.eq(code, 2)
    t.contains(err, "unknown option '--formt'")
    t.contains(err, "Did you mean '--format'?")
    t.contains(err, "loglens report --help")
  end)

  t.it("rejects invalid values", function()
    t.eq((run({ "report", "--top", "x", "access.log" })), 2)
    t.eq((run({ "report", "--format", "xml", "access.log" })), 2)
    t.eq((run({ "report", "--color", "purple", "access.log" })), 2)
    local code, _, err = run({ "json", "--top", "0", "access.log" })
    t.eq(code, 2)
    t.contains(err, "--top must be between 1 and 100")
    t.eq((run({ "json", "--top", "101", "access.log" })), 2)
  end)

  t.it("asks for an input", function()
    local code, _, err = run({ "report" })
    t.eq(code, 2)
    t.contains(err, "no input")
  end)

  t.it("suggests a command for a near miss, but not when such a file exists", function()
    local code, _, err = run({ "jsn", "access.log" })
    t.eq(code, 2)
    t.contains(err, "unknown command 'jsn'. Did you mean 'json'?")
    local status = run({ "jsn" }, { files = { jsn = LOG_TEXT } })
    t.eq(status, 0, "an existing file is simply analysed")
  end)

  t.it("validates the time window", function()
    local code, _, err = run({ "json", "--from", "yesterday", "access.log" })
    t.eq(code, 2)
    t.contains(err, "invalid --from value 'yesterday'")
    t.contains(select(3, run({ "json", "--to", "2026-13-40", "access.log" })), "invalid --to value")
    local reversed, _, message = run({ "json", "--from", "2026-11-12", "--to", "2026-11-10", "access.log" })
    t.eq(reversed, 2)
    t.contains(message, "--from must not be later than --to")
  end)

  t.it("validates the width, interval and frame options", function()
    t.contains(select(3, run({ "report", "--width", "10", "access.log" })), "--width must be between 40 and 240")
    t.eq((run({ "watch", "--interval", "0.01", "access.log" })), 2)
    t.eq((run({ "watch", "--interval", "120", "access.log" })), 2)
    t.eq((run({ "watch", "--frames", "0", "access.log" })), 2)
    t.eq((run({ "watch", "a.log", "b.log" })), 2)
    t.eq((run({ "watch" })), 2)
  end)
end)

t.describe("cli report", function()
  t.it("prints the dashboard without colour when output is not a terminal", function()
    local code, out, err = run({ "report", "access.log" })
    t.eq(code, 0)
    t.eq(err, "")
    for _, heading in ipairs({ "REQUESTS", "TRAFFIC", "TOP PATHS", "FINDINGS", "access.log" }) do
      t.contains(out, heading)
    end
    t.not_contains(out, "\27")
    t.eq(select(2, run({ "access.log" })), out, "report is the default command")
  end)

  t.it("decides about colour from the flags, the environment and the terminal", function()
    local function colored(argv, opts)
      return select(2, run(argv, opts)):find("\27[", 1, true) ~= nil
    end
    t.is_false(colored({ "access.log" }))
    t.is_true(colored({ "access.log", "--color", "always" }))
    t.is_true(colored({ "access.log" }, { tty = true }))
    t.is_false(colored({ "access.log", "--no-color" }, { tty = true }))
    t.is_false(colored({ "access.log", "--color", "never" }, { tty = true }))
    t.is_false(colored({ "access.log" }, { tty = true, env = { NO_COLOR = "1" } }))
    t.is_true(colored({ "access.log", "--color", "always" }, { env = { NO_COLOR = "1" } }), "a flag beats NO_COLOR")
    t.is_true(colored({ "access.log" }, { env = { FORCE_COLOR = "1" } }))
    t.is_false(colored({ "access.log" }, { env = { FORCE_COLOR = "0" } }))
    t.is_false(colored({ "access.log" }, { tty = true, env = { TERM = "dumb" } }))
  end)

  t.it("takes the width from --width, or from the terminal when there is one", function()
    local function widest(out)
      local most = 0
      for line in out:gmatch("[^\n]+") do
        most = math.max(most, util.visible_width(line))
      end
      return most
    end
    t.ge(widest(select(2, run({ "access.log" }))), 90)
    t.ge(widest(select(2, run({ "access.log", "--no-color" }, { tty = true, size = { 70, 30 } }))), 60)
    t.lt(widest(select(2, run({ "access.log", "--no-color" }, { tty = true, size = { 70, 30 } }))), 71)
    t.lt(widest(select(2, run({ "access.log", "--width", "60" }, { tty = true, size = { 70, 30 } }))), 61)
    t.ge(widest(select(2, run({ "access.log" }, { size = { 70, 30 } }))), 90, "redirected output ignores the terminal")
  end)

  t.it("can draw with ASCII only", function()
    local out = select(2, run({ "access.log", "--ascii", "--color", "always" }))
    t.not_contains((out:gsub("\27%[[%d;]*m", "")), "\226")
  end)

  t.it("analyses several files and standard input together", function()
    local files = { ["a.log"] = LOG_TEXT, ["b.log"] = LOG_TEXT }
    local _, out = run({ "json", "a.log", "b.log" }, { files = files })
    local single = decoded(select(2, run({ "json", "a.log" }, { files = files })))
    local both = decoded(out)
    t.eq(both.totals.requests, single.totals.requests * 2)
    t.eq(both.meta.sources, { "a.log", "b.log" })
    local _, piped = run({ "json", "-" }, { stdin = LOG_TEXT, files = {} })
    local from_stdin = decoded(piped)
    t.eq(from_stdin.meta.sources, { "stdin" })
    t.eq(from_stdin.totals.requests, single.totals.requests)
  end)

  t.it("reports unreadable and unparseable input", function()
    local code, out, err = run({ "report", "missing.log" })
    t.eq(code, 1)
    t.eq(out, "")
    t.contains(err, "missing.log: No such file or directory")
    local status, dashboard, message = run({ "report", "junk.log" }, { files = { ["junk.log"] = "hello\nworld\n" } })
    t.eq(status, 1)
    t.contains(dashboard, "Every line was rejected", "the dashboard still explains what happened")
    t.contains(message, "no line could be parsed as 'combined' (2 rejected)")
    local empty = run({ "report", "empty.log" }, { files = { ["empty.log"] = "" } })
    t.eq(empty, 0, "an empty log is not an error")
    local json_status = run({ "report", "--format", "json", "access.log" })
    t.eq(json_status, 1, "forcing the wrong format fails loudly")
  end)

  t.it("keeps a long unterminated line from being read into memory", function()
    local blob = string.rep("x", 300000)
    local code, out = run({ "json", "blob.log" }, { files = { ["blob.log"] = blob } })
    t.eq(code, 1)
    local summary = decoded(out)
    t.eq(summary.meta.lines.malformed, 1)
    t.contains(summary.meta.malformedSamples[1].reason, "line too long")
  end)
end)

t.describe("cli json", function()
  t.it("writes a valid loglens.summary/v1 document", function()
    local code, out = run({ "json", "access.log" })
    t.eq(code, 0)
    local summary = decoded(out)
    t.is_true(summary_module.validate(summary))
    t.eq(summary.schema, "loglens.summary/v1")
    t.eq(summary.meta.sources, { "access.log" })
    t.eq(out:sub(-2), "}\n")
    t.contains(out, "\n  \"meta\"", "pretty printed by default")
  end)

  t.it("prints one line with --compact", function()
    local _, out = run({ "json", "--compact", "access.log" })
    t.eq(select(2, out:gsub("\n", "\n")), 1)
    t.is_true(summary_module.validate(decoded(out)))
  end)

  t.it("honours --top, --format and the time window", function()
    t.eq(#decoded(select(2, run({ "json", "--top", "3", "access.log" }))).paths, 3)
    local forced = run({ "json", "--format", "combined", "access.log" })
    t.eq(forced, 0)
    local all = decoded(select(2, run({ "json", "access.log" })))
    local part = decoded(select(2, run({ "json", "--from", "2026-11-09T10:00", "--to", "2026-11-09T12:00",
      "access.log" })))
    t.lt(part.totals.requests, all.totals.requests)
    t.ge(part.totals.requests, 1)
    t.eq(part.meta.window.from, "2026-11-09T10:00:00Z")
    t.eq(part.meta.window.to, "2026-11-09T12:00:00Z")
    t.eq(part.meta.lines.outsideWindow, all.totals.requests - part.totals.requests)
    t.ok(part.totals.firstSeen >= "2026-11-09T10:00:00Z" and part.totals.lastSeen <= "2026-11-09T12:00:00Z")
    local day = decoded(select(2, run({ "json", "--from", "2026-11-09", "--to", "2026-11-09", "access.log" })))
    t.eq(day.meta.window.to, "2026-11-09T23:59:59Z", "a plain --to date covers the whole day")
    t.eq(day.totals.requests, all.totals.requests, "the sample is a single day")
  end)

  t.it("is reproducible and stamps the time from SOURCE_DATE_EPOCH when set", function()
    local env = { SOURCE_DATE_EPOCH = "1794400000" }
    local _, first = run({ "json", "access.log" }, { env = env })
    local _, second = run({ "json", "access.log" }, { env = env, now = 5 })
    t.eq(first, second)
    t.eq(decoded(first).meta.generatedAt, "2026-11-11T12:26:40Z")
  end)

  t.it("writes to a file and refuses to overwrite its own input", function()
    local code, out, err, probe = run({ "json", "access.log", "-o", "summary.json" })
    t.eq(code, 0)
    t.eq(out, "")
    t.contains(err, "wrote summary.json")
    t.is_true(summary_module.validate(decoded(probe.fs.files["summary.json"])))
    local refused, _, message = run({ "json", "access.log", "-o", "access.log" })
    t.eq(refused, 2)
    t.contains(message, "refusing to overwrite the input file")
  end)

  t.it("reports an output file that cannot be written", function()
    local env, probe = fakes.env({ files = { ["access.log"] = LOG_TEXT } })
    env.open = function(path, mode)
      if mode == "wb" then
        return nil, path .. ": Permission denied"
      end
      return probe.fs.open(path, mode)
    end
    t.eq(cli.main({ "json", "access.log", "-o", "/nope/out.json" }, env), 1)
    t.contains(probe.stderr(), "/nope/out.json: Permission denied")
  end)
end)

t.describe("cli --fail-on", function()
  t.it("exits with 3 when a finding reaches the severity", function()
    local code, out, err = run({ "json", "--fail-on", "high", "access.log" })
    t.eq(code, 3)
    t.ok(#out > 0, "the report is still written")
    t.matches(err, "%d+ findings at or above 'high'")
    t.eq((run({ "report", "--fail-on", "low", "access.log" })), 3)
    t.eq((run({ "json", "--fail-on", "critical", "access.log" })), 0)
    t.eq((run({ "json", "--fail-on", "high", "empty.log" }, { files = { ["empty.log"] = "" } })), 0)
    t.eq((run({ "json", "--fail-on", "urgent", "access.log" })), 2)
  end)
end)

t.describe("cli html", function()
  t.it("writes a self-contained report to stdout or to a file", function()
    local code, out = run({ "html", "access.log" })
    t.eq(code, 0)
    t.eq(out:sub(1, 15), "<!doctype html>")
    t.contains(out, "id=\"report-data\"")
    t.contains(out, "loglens report - access.log")
    local status, nothing, err, probe = run({ "html", "access.log", "-o", "report.html" })
    t.eq(status, 0)
    t.eq(nothing, "")
    t.contains(err, "wrote report.html")
    t.eq(probe.fs.files["report.html"], out)
  end)
end)

t.describe("cli watch", function()
  t.it("appends frames when output is not a terminal", function()
    local code, out = run({ "watch", "access.log", "--frames", "2", "--interval", "0.5" })
    t.eq(code, 0)
    t.not_contains(out, "\27")
    t.eq(select(2, out:gsub("REQUESTS", "")), 2)
    t.contains(out, "LIVE")
    t.contains(out, "access.log")
  end)

  t.it("repaints in place on a terminal and fits the height", function()
    local code, out, _, probe = run({ "watch", "access.log", "--frames", "3", "--interval", "0.25" },
      { tty = true, size = { 90, 30 } })
    t.eq(code, 0)
    t.contains(out, "\27[?25l")
    t.contains(out, "\27[H")
    t.not_contains(out, "\27[?1049h", "a frame limit keeps the last frame on screen")
    t.eq(out:sub(-6), "\27[?25h")
    t.eq(#probe.sleeps, 2)
  end)

  t.it("follows a file that is still missing and starts from its end with --new-only", function()
    local _, out = run({ "watch", "later.log", "--frames", "1" }, { files = {} })
    t.contains(out, "waiting for the file")
    local code, only_new = run({ "watch", "access.log", "--new-only", "--frames", "1" })
    t.eq(code, 0)
    t.contains(only_new, "Waiting for the first request.")
  end)

  t.it("reads standard input until it ends and leaves a plain report", function()
    local code, out = run({ "watch", "-", "--format", "combined" }, { stdin = LOG_TEXT, files = {} })
    t.eq(code, 0)
    t.not_contains(out, "LIVE")
    t.contains(out, "REQUESTS")
    t.contains(out, "stdin")
  end)

  t.it("refuses a path that cannot be read as a file", function()
    local env, probe = fakes.env({ files = {} })
    env.open = function()
      return {
        read = function()
          return nil, "Is a directory"
        end,
        close = function() end,
      }
    end
    t.eq(cli.main({ "watch", "somewhere" }, env), 1)
    t.contains(probe.stderr(), "somewhere: Is a directory")
  end)

  t.it("exits with 130 when interrupted", function()
    local env, probe = fakes.env({ files = { ["access.log"] = LOG_TEXT }, tty = true })
    env.sleep = function()
      error("src/loglens/watch.lua:90: interrupted!", 0)
    end
    t.eq(cli.main({ "watch", "access.log" }, env), 130)
    t.contains(probe.stdout(), "\27[?25h", "the cursor is back")
  end)
end)

t.describe("cli robustness", function()
  t.it("turns an unexpected failure into a message and exit status 1", function()
    local env, probe = fakes.env({})
    env.open = function()
      error("disk on fire", 0)
    end
    t.eq(cli.main({ "report", "access.log" }, env), 1)
    t.contains(probe.stderr(), "internal error: disk on fire")
  end)

  t.it("never fails on arbitrary arguments (fuzz)", function()
    -- (no "watch": it runs until interrupted, and no "html": every render hashes 200 KB of assets)
    local words = { "report", "json", "formats", "version", "--top", "5", "-n", "--format", "json", "access.log", "-",
      "--", "--fail-on", "high", "-o", "x", "--color", "always", "--from", "2026-11-10", "--no-color", "--bogus", "" }
    local state = 7
    for _ = 1, 150 do
      local argv = {}
      for i = 1, state % 5 + 1 do
        state = (state * 1103515245 + 12345) % 2147483648
        argv[i] = words[state % #words + 1]
      end
      state = (state * 1103515245 + 12345) % 2147483648
      local env, probe = fakes.env({ files = { ["access.log"] = "x\n" }, stdin = "" })
      local ok, code = pcall(cli.main, argv, env)
      t.ok(ok and math.type(code) == "integer", table.concat(argv, " ") .. " -> " .. tostring(code))
      t.not_contains(probe.stderr(), "internal error")
    end
  end)
end)
