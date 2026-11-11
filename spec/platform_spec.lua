local t = require("spec.support")
local platform = require("loglens.platform")

-- A system whose primitives are all fakes, so no branch touches the real machine.
local function system(overrides)
  local calls = { execute = {}, popen = {} }
  local s = {
    windows = false,
    socket = false,
    getenv = function()
      return nil
    end,
    clock = os.clock,
    execute = function(command)
      calls.execute[#calls.execute + 1] = command
      return true, "exit", 0
    end,
    popen = function(command)
      calls.popen[#calls.popen + 1] = command
      return nil
    end,
  }
  for key, value in pairs(overrides or {}) do
    s[key] = value
  end
  return s, calls
end

local function pipe(text)
  return {
    read = function()
      return text
    end,
    close = function() end,
  }
end

t.describe("platform.new", function()
  t.it("provides every hook the CLI and the live view use", function()
    local env = platform.new(system())
    for _, name in ipairs({ "open", "getenv", "now", "clock", "sleep", "is_tty", "terminal_size" }) do
      t.eq(type(env[name]), "function", name)
    end
    for _, name in ipairs({ "stdout", "stderr", "stdin" }) do
      t.ok(env[name], name)
    end
  end)

  t.it("works with the real primitives until a hook is used", function()
    t.eq(type(platform.new().sleep), "function")
  end)
end)

t.describe("platform is_tty", function()
  t.it("asks the shell on POSIX and understands every flavour of os.execute result", function()
    local function tty_with(execute)
      return platform.new(system({ execute = execute })).is_tty()
    end
    t.is_true(tty_with(function()
      return true, "exit", 0
    end))
    t.is_false(tty_with(function()
      return nil, "exit", 1
    end))
    t.is_true(tty_with(function()
      return 0
    end), "Lua 5.1 and LuaJIT return the exit status")
    t.is_false(tty_with(function()
      return 256
    end))
    t.is_nil(tty_with(function()
      error("os.execute is not available")
    end))
    local s, calls = system()
    platform.new(s).is_tty()
    t.eq(calls.execute, { "[ -t 1 ]" })
  end)

  t.it("trusts the terminal announcements on Windows", function()
    local function tty_on_windows(variables)
      return platform.new(system({
        windows = true,
        getenv = function(name)
          return variables[name]
        end,
      })).is_tty()
    end
    t.is_true(tty_on_windows({ WT_SESSION = "abc" }))
    t.is_true(tty_on_windows({ ConEmuANSI = "ON" }))
    t.is_true(tty_on_windows({ TERM = "xterm-256color" }))
    t.is_nil(tty_on_windows({ ConEmuANSI = "OFF" }))
    t.is_nil(tty_on_windows({}))
  end)
end)

t.describe("platform terminal_size", function()
  local function size_with(overrides)
    return platform.new(system(overrides)).terminal_size()
  end

  t.it("prefers COLUMNS and LINES", function()
    local variables = { COLUMNS = "132", LINES = "43" }
    local columns, rows = size_with({
      getenv = function(name)
        return variables[name]
      end,
    })
    t.eq(columns, 132)
    t.eq(rows, 43)
    variables.LINES = nil
    t.eq(select(2, size_with({
      getenv = function(name)
        return variables[name]
      end,
    })), nil)
  end)

  t.it("asks stty on POSIX", function()
    local s, calls = system({
      popen = function()
        return pipe("43 132\n")
      end,
    })
    local columns, rows = platform.new(s).terminal_size()
    t.eq(columns, 132)
    t.eq(rows, 43)
    t.eq(calls.execute, {}, "no shell command besides the pipe")
    t.is_nil((size_with({
      popen = function()
        return pipe("stty: 'standard input': Inappropriate ioctl for device\n")
      end,
    })))
    t.is_nil((size_with({
      popen = function()
        error("no processes here")
      end,
    })))
    t.is_nil((size_with()), "a failed pipe means unknown")
  end)

  t.it("reads `mode con` on Windows whatever language it is printed in", function()
    local function size_on_windows(text)
      return platform.new(system({
        windows = true,
        popen = function()
          return pipe(text)
        end,
      })).terminal_size()
    end
    local columns, rows = size_on_windows("Status for device CON:\n----------------------\n    Lines:          9001\n    Columns:        120\n    Keyboard rate:  31\n")
    t.eq(columns, 120)
    t.eq(rows, 9001)
    t.eq((size_on_windows("Status von Gerat CON:\n    Zeilen:         30\n    Spalten:        100\n")), 100)
    t.is_nil((size_on_windows("")))
  end)
end)

t.describe("platform sleep", function()
  t.it("uses the sleep command when there is one", function()
    local s, calls = system()
    platform.new(s).sleep(0.25)
    t.eq(calls.execute, { "sleep 0.250" })
  end)

  t.it("spins on the clock when the sleep command is unavailable", function()
    local now = 0
    local reads = 0
    local s = system({
      execute = function()
        return nil, "exit", 127
      end,
      clock = function()
        reads = reads + 1
        now = now + 0.01
        return now
      end,
    })
    platform.new(s).sleep(0.1)
    t.ge(reads, 10, "it waited until the clock passed the deadline")
    t.lt(reads, 30)
  end)

  t.it("spins on Windows instead of calling a shell", function()
    local now = 0
    local s, calls = system({
      windows = true,
      clock = function()
        now = now + 0.05
        return now
      end,
    })
    platform.new(s).sleep(0.2)
    t.eq(calls.execute, {})
    t.ge(now, 0.2)
  end)
end)
