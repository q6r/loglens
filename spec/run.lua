-- Test runner: `lua spec/run.lua [-v]` (works from any directory; plain Lua 5.3/5.4, no dependencies).
--
-- Spec files are listed explicitly (no directory listing is needed, so the same runner works in
-- sandboxes). Undeclared globals raise an error while the suite runs, which catches typos.
local script = (arg and arg[0]) or "spec/run.lua"
local root = script:match("^(.*[/\\])spec[/\\]run%.lua$") or ""
package.path = root .. "src/?.lua;" .. root .. "src/?/init.lua;" .. root .. "?.lua;" .. root
  .. "?/init.lua;" .. package.path

local verbose = false
for i = 1, #arg do
  if arg[i] == "-v" or arg[i] == "--verbose" then
    verbose = true
  end
end

setmetatable(_G, {
  __index = function(_, name)
    error("read of undeclared global '" .. tostring(name) .. "'", 2)
  end,
  __newindex = function(_, name)
    error("assignment to undeclared global '" .. tostring(name) .. "'", 2)
  end,
})

local support = require("spec.support")
support.root = root

local SPECS = {
  "spec.util_spec",
  "spec.json_spec",
  "spec.time_spec",
  "spec.sketches_spec",
  "spec.agents_spec",
  "spec.parser_spec",
  "spec.security_spec",
  "spec.stats_spec",
  "spec.analyzer_spec",
  "spec.terminal_spec",
  "spec.sha256_spec",
  "spec.args_spec",
  "spec.lines_spec",
  "spec.tail_spec",
  "spec.platform_spec",
  "spec.watch_spec",
  "spec.cli_spec",
  "spec.html_spec",
}

for _, name in ipairs(SPECS) do
  require(name)
end

io.stdout:write(string.format("loglens spec runner (%s)\n", _VERSION))
local result = support.run({ verbose = verbose })
io.stdout:write(string.format("\n%d tests, %d assertions, %d failures (%.2f s CPU)\n", result.tests,
  result.assertions, result.failures, result.seconds))
os.exit(result.failures == 0 and 0 or 1)
