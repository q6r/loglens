--- Minimal, dependency-free test framework used by `spec/run.lua`.
--
-- Spec files register suites with `describe` / `it` and make assertions with the helpers below.
-- Failures raise an error that carries a readable message; the runner collects them.
-- @module spec.support
local M = {}

local suites = {}
local current_path = {}
local assertion_count = 0

local format = string.format
local concat, sort = table.concat, table.sort

--- Serialises a value into a short, deterministic, human-readable string.
-- @param value any Lua value
-- @param depth number|nil maximum nesting depth (default 4)
-- @return string
function M.inspect(value, depth)
  depth = depth or 4
  local kind = type(value)
  if kind == "string" then
    local shown = value
    if #shown > 160 then
      shown = shown:sub(1, 160) .. "..."
    end
    return (format("%q", shown):gsub("\\\n", "\\n"))
  elseif kind ~= "table" then
    return tostring(value)
  end
  if depth <= 0 then
    return "{...}"
  end
  local keys = {}
  for key in pairs(value) do
    keys[#keys + 1] = key
  end
  sort(keys, function(a, b)
    local ta, tb = type(a), type(b)
    if ta ~= tb then
      return ta < tb
    end
    if ta == "number" or ta == "string" then
      return a < b
    end
    return tostring(a) < tostring(b)
  end)
  local parts = {}
  for i, key in ipairs(keys) do
    if i > 24 then
      parts[#parts + 1] = "..."
      break
    end
    local item = M.inspect(value[key], depth - 1)
    if type(key) == "number" and key == i then
      parts[#parts + 1] = item
    else
      parts[#parts + 1] = tostring(key) .. " = " .. item
    end
  end
  return "{ " .. concat(parts, ", ") .. " }"
end

--- Structural equality with cycle protection.
-- @param a any
-- @param b any
-- @return boolean
function M.deep_equal(a, b, seen)
  if a == b then
    return true
  end
  if type(a) ~= "table" or type(b) ~= "table" then
    return false
  end
  seen = seen or {}
  if seen[a] == b then
    return true
  end
  seen[a] = b
  for key, value in pairs(a) do
    if not M.deep_equal(value, b[key], seen) then
      return false
    end
  end
  for key in pairs(b) do
    if a[key] == nil then
      return false
    end
  end
  return true
end

local function fail(message, extra)
  if extra then
    message = extra .. "\n    " .. message
  end
  error(message, 3)
end

local function count()
  assertion_count = assertion_count + 1
end

--- Asserts deep equality.
function M.eq(actual, expected, message)
  count()
  if not M.deep_equal(actual, expected) then
    fail("expected " .. M.inspect(expected) .. "\n         got " .. M.inspect(actual), message)
  end
end

--- Asserts inequality.
function M.neq(actual, unexpected, message)
  count()
  if M.deep_equal(actual, unexpected) then
    fail("did not expect " .. M.inspect(actual), message)
  end
end

--- Asserts that the value is truthy.
function M.ok(value, message)
  count()
  if not value then
    fail("expected a truthy value, got " .. M.inspect(value), message)
  end
end

--- Asserts that the value is nil.
function M.is_nil(value, message)
  count()
  if value ~= nil then
    fail("expected nil, got " .. M.inspect(value), message)
  end
end

--- Asserts that the value is exactly `true`.
function M.is_true(value, message)
  count()
  if value ~= true then
    fail("expected true, got " .. M.inspect(value), message)
  end
end

--- Asserts that the value is exactly `false`.
function M.is_false(value, message)
  count()
  if value ~= false then
    fail("expected false, got " .. M.inspect(value), message)
  end
end

--- Asserts that two numbers differ by at most `tolerance`.
function M.near(actual, expected, tolerance, message)
  count()
  if type(actual) ~= "number" or math.abs(actual - expected) > tolerance then
    fail(format("expected %s +/- %s, got %s", tostring(expected), tostring(tolerance),
      M.inspect(actual)), message)
  end
end

--- Asserts `actual < limit`.
function M.lt(actual, limit, message)
  count()
  if not (type(actual) == "number" and actual < limit) then
    fail(format("expected %s < %s", M.inspect(actual), tostring(limit)), message)
  end
end

--- Asserts `actual >= limit`.
function M.ge(actual, limit, message)
  count()
  if not (type(actual) == "number" and actual >= limit) then
    fail(format("expected %s >= %s", M.inspect(actual), tostring(limit)), message)
  end
end

--- Asserts that `text` contains the plain substring `needle`.
function M.contains(text, needle, message)
  count()
  if type(text) ~= "string" or not text:find(needle, 1, true) then
    fail("expected " .. M.inspect(text) .. "\n to contain " .. M.inspect(needle), message)
  end
end

--- Asserts that `text` does not contain the plain substring `needle`.
function M.not_contains(text, needle, message)
  count()
  if type(text) == "string" and text:find(needle, 1, true) then
    fail("expected " .. M.inspect(text) .. "\n NOT to contain " .. M.inspect(needle), message)
  end
end

--- Asserts that `text` matches the Lua pattern.
function M.matches(text, pattern, message)
  count()
  if type(text) ~= "string" or not text:find(pattern) then
    fail("expected " .. M.inspect(text) .. "\n to match " .. M.inspect(pattern), message)
  end
end

--- Asserts that `fn` raises an error whose message contains `needle` (plain) when given.
-- @return string the error message
function M.raises(fn, needle, message)
  count()
  local ok, err = pcall(fn)
  if ok then
    fail("expected an error, but the call succeeded", message)
  end
  err = tostring(err)
  if needle and not err:find(needle, 1, true) then
    fail("expected error containing " .. M.inspect(needle) .. ", got " .. M.inspect(err), message)
  end
  return err
end

--- Project root as a path prefix ("" or ending in a slash); `spec/run.lua` sets it so fixtures
-- resolve from any working directory.
M.root = ""

--- Reads a whole file.
-- @param path string
-- @return string|nil contents
-- @return string|nil error message
function M.read_file(path)
  local file, err = io.open(path, "rb")
  if not file then
    return nil, err
  end
  local data = file:read("a")
  file:close()
  return data
end

local function first_difference(actual, expected)
  local a, e = M.lines_of(actual), M.lines_of(expected)
  for i = 1, math.max(#a, #e) do
    if a[i] ~= e[i] then
      return format("first difference at line %d:\n    expected: %s\n    actual:   %s", i,
        M.inspect(e[i] or "<end of file>"), M.inspect(a[i] or "<end of output>"))
    end
  end
  return "contents differ only in the final newline"
end

--- Compares text with the golden file `spec/fixtures/golden/<name>`. Run with the environment
-- variable `UPDATE_GOLDEN=1` to (re)write the file instead; review the diff before committing.
-- @param name string file name inside spec/fixtures/golden
-- @param actual string
function M.golden(name, actual)
  count()
  local path = M.root .. "spec/fixtures/golden/" .. name
  local ok, update = pcall(os.getenv, "UPDATE_GOLDEN")
  if ok and update and update ~= "" then
    local file = assert(io.open(path, "wb"))
    file:write(actual)
    file:close()
    return
  end
  local expected, err = M.read_file(path)
  if not expected then
    fail("missing golden file " .. path .. " (" .. tostring(err) .. "); run with UPDATE_GOLDEN=1")
  end
  if actual ~= expected then
    fail("output differs from golden file " .. name .. "\n  " .. first_difference(actual, expected)
      .. "\n  (set UPDATE_GOLDEN=1 to accept the new output)")
  end
end

--- Splits text into lines (no trailing empty element for a final newline).
-- @param text string
-- @return string[]
function M.lines_of(text)
  local out = {}
  for line in (text .. "\n"):gmatch("(.-)\n") do
    out[#out + 1] = line
  end
  if out[#out] == "" then
    out[#out] = nil
  end
  return out
end

--- Registers a group of tests.
-- @param name string
-- @param body function called immediately; calls `it` / nested `describe`
function M.describe(name, body)
  current_path[#current_path + 1] = name
  body()
  current_path[#current_path] = nil
end

--- Registers one test case.
-- @param name string
-- @param fn function the test body
function M.it(name, fn)
  suites[#suites + 1] = {
    suite = current_path[1] or "(root)",
    name = concat(current_path, " > ") .. " > " .. name,
    fn = fn,
  }
end

local function trim_traceback(message)
  local lines = {}
  for line in tostring(message):gmatch("[^\n]+") do
    if not line:find("spec/support.lua", 1, true) and not line:find("[C]: in function 'xpcall'", 1, true)
        and not line:find("(...tail calls...)", 1, true) then
      lines[#lines + 1] = line
    end
    if #lines >= 14 then
      break
    end
  end
  return concat(lines, "\n")
end

--- Runs every registered test.
-- @param opts table|nil `{ verbose = boolean, out = file-like }`
-- @return table `{ tests, failures, assertions, seconds, failed = { { name, message }... } }`
function M.run(opts)
  opts = opts or {}
  local out = opts.out or io.stdout
  local started = os.clock()
  local failed, passed = {}, 0
  local per_suite, order = {}, {}
  for _, case in ipairs(suites) do
    local stats = per_suite[case.suite]
    if not stats then
      stats = { tests = 0, failed = 0 }
      per_suite[case.suite] = stats
      order[#order + 1] = case.suite
    end
    stats.tests = stats.tests + 1
    local ok, err = xpcall(case.fn, function(message)
      return trim_traceback(debug.traceback(tostring(message), 2))
    end)
    if ok then
      passed = passed + 1
      if opts.verbose then
        out:write("  ok    ", case.name, "\n")
      end
    else
      stats.failed = stats.failed + 1
      failed[#failed + 1] = { name = case.name, message = err }
    end
  end
  for _, name in ipairs(order) do
    local stats = per_suite[name]
    out:write(format("%-5s %-28s %3d tests\n", stats.failed == 0 and "ok" or "FAIL", name, stats.tests))
  end
  for _, item in ipairs(failed) do
    out:write("\nFAILED: ", item.name, "\n  ", (item.message:gsub("\n", "\n  ")), "\n")
  end
  return {
    tests = #suites,
    passed = passed,
    failures = #failed,
    assertions = assertion_count,
    seconds = os.clock() - started,
    failed = failed,
  }
end

return M
