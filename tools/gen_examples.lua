--- Regenerates everything under `examples/`: sample logs in each supported format, the JSON
-- summary and the HTML report of the main sample. Output is deterministic (seeded generator and a
-- fixed clock), so a diff after regeneration means the code changed.
--
--     lua tools/gen_examples.lua          (run from the project root)
-- @script tools.gen_examples
package.path = "src/?.lua;src/?/init.lua;?.lua;" .. package.path

local analyzer = require("loglens.analyzer")
local html = require("loglens.render.html")
local loggen = require("tools.loggen")
local summary_module = require("loglens.summary")
local time = require("loglens.time")

local GENERATED_AT = time.parse_iso("2026-11-16T12:00:00Z")

local function write(path, text)
  local file = assert(io.open(path, "wb"))
  assert(file:write(text))
  file:close()
  print(string.format("wrote %-26s %8d bytes", path, #text))
end

local function log_text(lines)
  return table.concat(lines, "\n") .. "\n"
end

-- The main sample: a week of a small shop, with a scanner, a brute-force run, injection attempts
-- and an outage of the checkout API hidden in ordinary traffic.
local main_lines = loggen.lines({ seed = 2026, count = 2600, duration = 7 * 86400 })
write("examples/access.log", log_text(main_lines))

-- The other formats are short: enough to try `--format` and auto-detection.
for _, sample in ipairs({
  { "examples/common.log", "common" },
  { "examples/app.jsonl", "json" },
  { "examples/caddy.log", "caddy" },
}) do
  write(sample[1], log_text(loggen.lines({ seed = 7, count = 150, duration = 6 * 3600, attacks = false,
    format = sample[2] })))
end

local summary = analyzer.analyze_lines(main_lines, { sources = { "examples/access.log" }, now = GENERATED_AT })
write("examples/summary.json", summary_module.encode(summary) .. "\n")
write("examples/report.html", assert(html.render(summary)))
