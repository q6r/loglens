--- The only module that talks to the operating system: standard streams, environment, clock, sleep
-- and the terminal. The CLI and the live view receive these as a plain table (`env`), so they run
-- unchanged against fakes in the specs.
--
-- Pure Lua has no terminal or sleep API, so this module borrows from the environment:
--   * colour and size come from `NO_COLOR`, `FORCE_COLOR`, `COLUMNS` and `LINES`, then from
--     `[ -t 1 ]` and `stty size` on POSIX or `mode con` on Windows (through `io.popen`);
--   * sleeping uses LuaSocket when it is installed, `sleep` on POSIX, and a short busy-wait on
--     Windows, where nothing else is available to plain Lua.
-- Every call that spawns a process is guarded, so a restricted environment degrades to defaults.
-- The primitives (`os.execute`, `io.popen`, `os.getenv`, `os.clock`) can be replaced through
-- `new`'s argument, which is how the specs exercise each branch without touching the system.
-- @module loglens.platform
local M = {}

-- Waits by spinning: the last resort when nothing better exists (it keeps one core busy).
local function busy_wait(clock, seconds)
  local stop = clock() + seconds
  while clock() < stop do
  end
end

local function read_command(s, command)
  if not s.popen then
    return nil
  end
  local ok, pipe = pcall(s.popen, command, "r")
  if not ok or not pipe then
    return nil
  end
  local text = pipe:read("a")
  pipe:close()
  return text
end

-- Is standard output a terminal? `nil` means "cannot tell".
local function stdout_is_tty(s)
  if not s.windows then
    local ok, status = pcall(s.execute, "[ -t 1 ]")
    if not ok then
      return nil
    end
    if type(status) == "number" then -- Lua 5.1 and LuaJIT return the exit status
      return status == 0
    end
    return status == true
  end
  -- Windows has no isatty in plain Lua: trust terminals that announce themselves.
  if s.getenv("WT_SESSION") or s.getenv("ANSICON") or s.getenv("ConEmuANSI") == "ON"
      or s.getenv("TERM_PROGRAM") or s.getenv("TERM") then
    return true
  end
  return nil
end

-- Columns and rows of the terminal, from the environment or from the system.
local function terminal_size(s)
  local columns, rows = tonumber(s.getenv("COLUMNS")), tonumber(s.getenv("LINES"))
  if columns and columns > 0 then
    return columns, rows
  end
  if not s.windows then
    local text = read_command(s, "stty size </dev/tty 2>/dev/null")
    local r, c = (text or ""):match("(%d+)%s+(%d+)")
    if r then
      return tonumber(c), tonumber(r)
    end
    return nil
  end
  -- `mode con` prints "Lines: n" then "Columns: n" (the labels are localised, the order is not).
  local numbers = {}
  for value in (read_command(s, "mode con") or ""):gmatch(":%s*(%d+)") do
    numbers[#numbers + 1] = tonumber(value)
  end
  if numbers[2] and numbers[2] > 0 then
    return numbers[2], numbers[1]
  end
  return nil
end

local function make_sleep(s)
  if s.socket and type(s.socket.sleep) == "function" then
    return s.socket.sleep
  end
  if s.windows then
    return function(seconds)
      busy_wait(s.clock, seconds)
    end
  end
  return function(seconds)
    local started, status = pcall(s.execute, string.format("sleep %.3f", seconds))
    if not (started and status) then
      busy_wait(s.clock, seconds)
    end
  end
end

--- Builds the real environment.
-- @param system table|nil replacements for the primitives: `windows` (boolean), `execute`, `popen`,
--   `getenv`, `clock` and `socket` (LuaSocket, or `false` for none); by default the real ones
-- @return table `{ stdout, stderr, stdin, open, getenv, now, clock, sleep, is_tty(), terminal_size() }`
function M.new(system)
  system = system or {}
  local s = {
    windows = system.windows,
    execute = system.execute or os.execute,
    popen = system.popen or io.popen,
    getenv = system.getenv or os.getenv,
    clock = system.clock or os.clock,
    socket = system.socket,
  }
  if s.windows == nil then
    s.windows = package.config:sub(1, 1) == "\\"
  end
  if s.socket == nil then
    local ok, loaded = pcall(require, "socket")
    s.socket = ok and type(loaded) == "table" and loaded
  end
  return {
    stdout = io.stdout,
    stderr = io.stderr,
    stdin = io.stdin,
    open = io.open,
    getenv = s.getenv,
    now = os.time,
    clock = s.clock,
    sleep = make_sleep(s),
    is_tty = function()
      return stdout_is_tty(s)
    end,
    terminal_size = function()
      return terminal_size(s)
    end,
  }
end

return M
