--- Command-line interface: `loglens [report|json|html|watch|formats|version|help] [options] <file|->...`.
--
-- `main(argv, env)` parses the arguments, runs one command and returns the exit status. It never
-- calls `os.exit` and reaches the outside world only through `env` (see `loglens.platform`), so the
-- specs run it with fake streams, files, clocks and terminals.
--
-- Exit status: 0 success, 1 runtime failure (unreadable input, nothing parsed), 2 usage error,
-- 3 a finding reached `--fail-on`, 130 interrupted.
-- @module loglens.cli
local analyzer_module = require("loglens.analyzer")
local args = require("loglens.args")
local html = require("loglens.render.html")
local lines = require("loglens.lines")
local parser = require("loglens.parser")
local summary_module = require("loglens.summary")
local tail = require("loglens.tail")
local terminal = require("loglens.render.terminal")
local time = require("loglens.time")
local util = require("loglens.util")
local version = require("loglens.version")
local watch = require("loglens.watch")

local M = {}

local EXIT = { ok = 0, failure = 1, usage = 2, findings = 3, interrupted = 130 }
M.EXIT = EXIT

local SEVERITY_RANK = { info = 1, low = 2, medium = 3, high = 4, critical = 5 }

local FORMAT_CHOICES = { "auto" }
for _, name in ipairs(parser.names()) do
  FORMAT_CHOICES[#FORMAT_CHOICES + 1] = name
end

local OPTIONS = {
  format = { name = "format", short = "f", value = "NAME", choices = FORMAT_CHOICES,
    help = "log format: auto (default), " .. table.concat(parser.names(), ", ") },
  from = { name = "from", value = "TIME",
    help = "ignore requests before TIME (ISO 8601, e.g. 2026-11-10T14:00)" },
  to = { name = "to", value = "TIME",
    help = "ignore requests after TIME (a plain date covers the whole day)" },
  top = { name = "top", short = "n", value = "N", kind = "integer",
    help = "rows per ranked list, 1-100 (default 10)" },
  color = { name = "color", value = "WHEN", choices = { "auto", "always", "never" },
    help = "colour: auto (default), always or never" },
  no_color = { name = "no-color", help = "same as --color never" },
  ascii = { name = "ascii", help = "draw with plain ASCII instead of block characters" },
  width = { name = "width", value = "COLS", kind = "integer",
    help = "dashboard width, 40-240 (default: the terminal width, or 100)" },
  output = { name = "output", short = "o", value = "FILE",
    help = "write to FILE instead of standard output" },
  compact = { name = "compact", help = "print the JSON on a single line" },
  fail_on = { name = "fail-on", value = "SEVERITY",
    choices = { "info", "low", "medium", "high", "critical" },
    help = "exit with status 3 when a finding of at least this severity exists" },
  interval = { name = "interval", value = "SECONDS", kind = "number",
    help = "seconds between redraws, 0.05-60 (default 0.25)" },
  frames = { name = "frames", value = "N", kind = "integer",
    help = "stop after N frames (default: run until the input ends or Ctrl+C)" },
  new_only = { name = "new-only", help = "skip what the file already holds, show new requests only" },
  help = { name = "help", short = "h", help = "show this help" },
}

local function list(...)
  return { ... }
end

local COMMANDS = {
  report = {
    summary = "dashboard for a finished log (the default command)",
    usage = "loglens [report] [options] <file|->...",
    options = list(OPTIONS.format, OPTIONS.from, OPTIONS.to, OPTIONS.top, OPTIONS.color,
      OPTIONS.no_color, OPTIONS.ascii, OPTIONS.width, OPTIONS.fail_on, OPTIONS.help),
  },
  json = {
    summary = "machine-readable summary (schema loglens.summary/v1)",
    usage = "loglens json [options] <file|->...",
    options = list(OPTIONS.format, OPTIONS.from, OPTIONS.to, OPTIONS.top, OPTIONS.output,
      OPTIONS.compact, OPTIONS.fail_on, OPTIONS.help),
  },
  html = {
    summary = "self-contained HTML report (works offline, no external requests)",
    usage = "loglens html [options] <file|->...",
    options = list(OPTIONS.format, OPTIONS.from, OPTIONS.to, OPTIONS.top, OPTIONS.output,
      OPTIONS.fail_on, OPTIONS.help),
  },
  watch = {
    summary = "follow a growing log and redraw the dashboard live",
    usage = "loglens watch [options] <file|->",
    options = list(OPTIONS.format, OPTIONS.from, OPTIONS.to, OPTIONS.top, OPTIONS.interval,
      OPTIONS.frames, OPTIONS.new_only, OPTIONS.color, OPTIONS.no_color, OPTIONS.ascii,
      OPTIONS.width, OPTIONS.help),
  },
  formats = { summary = "list the supported log formats", usage = "loglens formats", options = list(OPTIONS.help) },
  version = { summary = "print the version", usage = "loglens version", options = list(OPTIONS.help) },
}
local COMMAND_ORDER = { "report", "json", "html", "watch", "formats", "version" }

local function command_names()
  local names = {}
  for i, name in ipairs(COMMAND_ORDER) do
    names[i] = name
  end
  names[#names + 1] = "help"
  return names
end

local function overview()
  local out = { "loglens " .. version .. " - analyse web-server access logs (nginx, Apache, Caddy)", "",
    "Usage:" }
  for _, name in ipairs(COMMAND_ORDER) do
    local command = COMMANDS[name]
    out[#out + 1] = string.format("  %-44s %s", command.usage, command.summary)
  end
  out[#out + 1] = ""
  out[#out + 1] = "Use '-' as the file name to read standard input. 'loglens <command> --help' lists the"
  out[#out + 1] = "options of one command. Exit status: 0 ok, 1 failure, 2 usage error, 3 --fail-on."
  return table.concat(out, "\n") .. "\n"
end

local function command_help(name)
  local command = COMMANDS[name]
  local description = command.summary:gsub("^%l", string.upper)
  local out = { "Usage: " .. command.usage, "", description, "", "Options:" }
  for _, line in ipairs(args.help_lines(command.options)) do
    out[#out + 1] = line
  end
  return table.concat(out, "\n") .. "\n"
end

---------------------------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------------------------

local function complain(env, message)
  env.stderr:write("loglens: " .. message .. "\n")
end

local function fail(env, code, message)
  complain(env, message)
  return code
end

local function display_name(path)
  return path == "-" and "stdin" or path
end

-- Epoch seconds for --from / --to; a plain date given to --to covers the whole day.
local function parse_time(text, name)
  local epoch, err = time.parse_value(text)
  if not epoch then
    return nil, string.format("invalid --%s value '%s': %s", name, text, err)
  end
  if name == "to" and text:match("^%d%d%d%d%-%d%d%-%d%d$") then
    epoch = epoch + 86399
  end
  return epoch
end

-- Validates the options shared by every analysing command and builds the analyzer.
local function build_analyzer(options, env, sources)
  local from, to, err
  if options.from then
    from, err = parse_time(options.from, "from")
    if not from then
      return nil, err
    end
  end
  if options.to then
    to, err = parse_time(options.to, "to")
    if not to then
      return nil, err
    end
  end
  if from and to and from > to then
    return nil, "--from must not be later than --to"
  end
  if options.top and (options.top < 1 or options.top > 100) then
    return nil, "--top must be between 1 and 100"
  end
  local epoch = tonumber(env.getenv("SOURCE_DATE_EPOCH"))
  return analyzer_module.new({
    format = options.format or "auto",
    top = options.top or 10,
    from = from,
    to = to,
    sources = sources,
    now = epoch or env.now,
  })
end

local function read_inputs(files, analyzer, env)
  local function feed(line)
    analyzer:feed(line)
  end
  for _, path in ipairs(files) do
    local stream, file = env.stdin, nil
    if path ~= "-" then
      local err
      file, err = env.open(path, "rb")
      if not file then
        return nil, err
      end
      stream = file
    elseif not stream then
      return nil, "standard input is not available"
    end
    local ok, err = lines.read_stream(stream, analyzer.opts.max_line_bytes, feed)
    if file then
      file:close()
    end
    if not ok then
      return nil, display_name(path) .. ": " .. err
    end
  end
  return true
end

-- Runs the analysis for report, json and html. Returns the summary, or nil and an exit status.
local function analyze(parsed, env)
  local files = parsed.args
  if #files == 0 then
    return nil, fail(env, EXIT.usage, "no input: pass a log file, or '-' to read standard input")
  end
  if parsed.options.output then
    for _, path in ipairs(files) do
      if path == parsed.options.output then
        return nil, fail(env, EXIT.usage, "refusing to overwrite the input file '" .. path .. "'")
      end
    end
  end
  local sources = {}
  for i, path in ipairs(files) do
    sources[i] = display_name(path)
  end
  local analyzer, err = build_analyzer(parsed.options, env, sources)
  if not analyzer then
    return nil, fail(env, EXIT.usage, err)
  end
  local ok, read_error = read_inputs(files, analyzer, env)
  if not ok then
    return nil, fail(env, EXIT.failure, read_error)
  end
  return analyzer:summary()
end

-- Status for a finished analysis: nothing parseable is a failure, --fail-on gates on findings.
local function verdict(summary, options, env)
  local counts = summary.meta.lines
  if counts.parsed == 0 and counts.malformed > 0 then
    return fail(env, EXIT.failure, string.format(
      "no line could be parsed as '%s' (%d rejected); check --format", summary.meta.format,
      counts.malformed))
  end
  if options.fail_on then
    local threshold, hits = SEVERITY_RANK[options.fail_on], 0
    for _, finding in ipairs(summary.findings) do
      if SEVERITY_RANK[finding.severity] >= threshold then
        hits = hits + 1
      end
    end
    if hits > 0 then
      return fail(env, EXIT.findings, string.format("%d finding%s at or above '%s'", hits,
        hits == 1 and "" or "s", options.fail_on))
    end
  end
  return EXIT.ok
end

local function wants_color(options, env, tty)
  if options.no_color or options.color == "never" then
    return false
  end
  if options.color == "always" then
    return true
  end
  local no_color, force = env.getenv("NO_COLOR"), env.getenv("FORCE_COLOR")
  if no_color and no_color ~= "" then
    return false
  end
  if force and force ~= "" and force ~= "0" then
    return true
  end
  if env.getenv("TERM") == "dumb" then
    return false
  end
  return tty == true
end

local function width_problem(options)
  if options.width and (options.width < 40 or options.width > 240) then
    return "--width must be between 40 and 240"
  end
  return nil
end

-- The dashboard width: --width, else the terminal's, else 100 (also when output is redirected).
local function dashboard_width(options, env, tty)
  if options.width then
    return options.width
  end
  if tty and env.terminal_size then
    local columns = env.terminal_size()
    if columns then
      return columns
    end
  end
  return 100
end

local function write_output(env, path, text)
  if not path then
    env.stdout:write(text)
    return true
  end
  local file, err = env.open(path, "wb")
  if not file then
    return nil, err
  end
  local ok, write_error = file:write(text)
  file:close()
  if not ok then
    return nil, path .. ": " .. tostring(write_error)
  end
  complain(env, string.format("wrote %s (%s)", path, util.fmt_bytes(#text)))
  return true
end

---------------------------------------------------------------------------------------------
-- Commands
---------------------------------------------------------------------------------------------

local function run_report(parsed, env)
  local problem = width_problem(parsed.options)
  if problem then
    return fail(env, EXIT.usage, problem)
  end
  local summary, status = analyze(parsed, env)
  if not summary then
    return status
  end
  local tty = env.is_tty and env.is_tty() or false
  env.stdout:write(terminal.render(summary, {
    width = dashboard_width(parsed.options, env, tty),
    color = wants_color(parsed.options, env, tty),
    ascii = parsed.options.ascii,
  }))
  return verdict(summary, parsed.options, env)
end

local function run_json(parsed, env)
  local summary, status = analyze(parsed, env)
  if not summary then
    return status
  end
  local text = summary_module.encode(summary, { indent = parsed.options.compact and 0 or 2 }) .. "\n"
  local ok, err = write_output(env, parsed.options.output, text)
  if not ok then
    return fail(env, EXIT.failure, err)
  end
  return verdict(summary, parsed.options, env)
end

local function run_html(parsed, env)
  local summary, status = analyze(parsed, env)
  if not summary then
    return status
  end
  local text, render_error = html.render(summary)
  if not text then
    return fail(env, EXIT.failure, render_error)
  end
  local ok, err = write_output(env, parsed.options.output, text)
  if not ok then
    return fail(env, EXIT.failure, err)
  end
  return verdict(summary, parsed.options, env)
end

local function run_watch(parsed, env)
  local options = parsed.options
  if #parsed.args ~= 1 then
    return fail(env, EXIT.usage, "watch follows exactly one file, or '-' for standard input")
  end
  local path = parsed.args[1]
  local interval = options.interval or 0.25
  if interval < 0.05 or interval > 60 then
    return fail(env, EXIT.usage, "--interval must be between 0.05 and 60 seconds")
  end
  if options.frames and options.frames < 1 then
    return fail(env, EXIT.usage, "--frames must be at least 1")
  end
  local problem = width_problem(options)
  if problem then
    return fail(env, EXIT.usage, problem)
  end
  local tty = env.is_tty and env.is_tty() or false
  local analyzer, err = build_analyzer(options, env, { display_name(path) })
  if not analyzer then
    return fail(env, EXIT.usage, err)
  end

  local source
  if path == "-" then
    if not env.stdin then
      return fail(env, EXIT.failure, "standard input is not available")
    end
    source = tail.stream(env.stdin)
  else
    local probe = env.open(path, "rb")
    if probe then
      local _, read_error = probe:read(0)
      probe:close()
      if read_error then
        return fail(env, EXIT.failure, path .. ": " .. read_error)
      end
    end
    source = tail.file(path, { open = env.open, max_line_bytes = analyzer.opts.max_line_bytes,
      new_only = options.new_only })
  end

  local reason, message = watch.run({
    analyzer = analyzer,
    source = source,
    interval = interval,
    frames = options.frames,
    redraw = tty,
    render = { color = wants_color(options, env, tty), ascii = options.ascii, width = options.width },
  }, {
    write = function(text)
      env.stdout:write(text)
      env.stdout:flush()
    end,
    sleep = env.sleep,
    clock = env.clock,
    size = tty and env.terminal_size or nil,
  })
  if reason == "error" then
    return fail(env, EXIT.failure, display_name(path) .. ": " .. tostring(message))
  elseif reason == "interrupted" then
    return EXIT.interrupted
  end
  return EXIT.ok
end

local function run_formats(_, env)
  local out = {}
  for _, format in ipairs(parser.FORMATS) do
    out[#out + 1] = format.name
    for _, line in ipairs(util.wrap(format.description, 74)) do
      out[#out + 1] = "  " .. line
    end
    out[#out + 1] = "  e.g. " .. format.example
    out[#out + 1] = ""
  end
  out[#out] = nil
  env.stdout:write(table.concat(out, "\n") .. "\n")
  return EXIT.ok
end

local function run_version(_, env)
  env.stdout:write(string.format("loglens %s (%s)\n", version, _VERSION))
  return EXIT.ok
end

local RUNNERS = {
  report = run_report,
  json = run_json,
  html = run_html,
  watch = run_watch,
  formats = run_formats,
  version = run_version,
}

---------------------------------------------------------------------------------------------
-- Entry point
---------------------------------------------------------------------------------------------

-- A first argument that is neither a command nor an option is a file to analyse, unless it is a
-- near miss of a command name and no such file exists.
local function misspelled_command(word, env)
  local guess = util.suggest(word, command_names())
  if not guess then
    return nil
  end
  local file = env.open(word, "rb")
  if file then
    file:close()
    return nil
  end
  return guess
end

--- Runs the command line.
-- @param argv string[] the arguments after the program name (the global `arg` works)
-- @param env table hooks, see `loglens.platform.new`; `stdout` and `stderr` are required
-- @return number exit status
function M.main(argv, env)
  local words = {}
  for i = 1, #argv do
    words[i] = argv[i]
  end
  env.open = env.open or io.open
  env.getenv = env.getenv or os.getenv
  env.now = env.now or os.time
  env.clock = env.clock or os.clock

  local first = words[1]
  if first == nil then
    env.stderr:write(overview())
    return EXIT.usage
  elseif first == "--help" or first == "-h" or first == "help" then
    local topic = first == "help" and words[2] or nil
    env.stdout:write(topic and COMMANDS[topic] and command_help(topic) or overview())
    return EXIT.ok
  elseif first == "--version" or first == "-V" then
    return run_version(nil, env)
  end

  local name = "report"
  if COMMANDS[first] then
    name = first
    table.remove(words, 1)
  elseif first:sub(1, 1) ~= "-" and first ~= "-" then
    local guess = misspelled_command(first, env)
    if guess then
      return fail(env, EXIT.usage, string.format("unknown command '%s'. Did you mean '%s'?", first, guess))
    end
  end

  local command = COMMANDS[name]
  local parsed, err = args.parse(words, command.options)
  if not parsed then
    return fail(env, EXIT.usage, err .. " (see 'loglens " .. name .. " --help')")
  end
  if parsed.options.help then
    env.stdout:write(command_help(name))
    return EXIT.ok
  end
  local ok, status = xpcall(RUNNERS[name], function(message)
    message = tostring(message)
    return env.getenv("LOGLENS_DEBUG") and debug.traceback(message, 2) or message
  end, parsed, env)
  if not ok then
    if status:find("interrupted", 1, true) then
      return EXIT.interrupted
    end
    return fail(env, EXIT.failure, "internal error: " .. status)
  end
  return status
end

return M
