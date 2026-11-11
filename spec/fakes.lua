--- Fake operating-system pieces for the specs: an in-memory file system, standard streams, a clock
-- that only moves when something sleeps, and a ready-made `env` for `loglens.cli`.
-- @module spec.fakes
local M = {}

--- An in-memory file system with the `io.open` subset the code uses (`seek`, `read(n)`, `write`,
-- `close`). Read handles see a snapshot taken when they were opened.
-- @param files table|nil initial contents, path -> string
-- @return table fs with `open`, `files`, `opened`, `closed`, `unseekable` (paths that cannot seek)
function M.fs(files)
  local fs = { files = files or {}, opened = 0, closed = 0, unseekable = {} }

  function fs.open(path, mode)
    mode = mode or "r"
    if mode:find("w", 1, true) then
      fs.files[path] = ""
      fs.opened = fs.opened + 1
      local handle = {}
      function handle:write(text)
        fs.files[path] = fs.files[path] .. text
        return self
      end
      function handle:close()
        fs.closed = fs.closed + 1
      end
      return handle
    end
    local snapshot = fs.files[path]
    if snapshot == nil then
      return nil, path .. ": No such file or directory"
    end
    fs.opened = fs.opened + 1
    local position = 0
    local handle = {}
    function handle:seek(whence, offset)
      if fs.unseekable[path] then
        return nil, "Illegal seek"
      end
      offset = offset or 0
      if whence == "set" then
        position = offset
      elseif whence == "end" then
        position = #snapshot + offset
      else
        position = position + offset
      end
      return position
    end
    function handle:read(count)
      if count == 0 then
        return position < #snapshot and "" or nil
      end
      if position >= #snapshot then
        return nil
      end
      local chunk = snapshot:sub(position + 1, position + count)
      position = position + #chunk
      return chunk
    end
    function handle:close()
      fs.closed = fs.closed + 1
    end
    return handle
  end

  return fs
end

--- A readable stream over a string (`read(n)` and `read("l")`), like `io.stdin`.
-- @param text string
-- @return table
function M.stdin(text)
  local position = 1
  local stream = {}
  function stream:read(what)
    if position > #text then
      return nil
    end
    if what == "l" then
      local newline = text:find("\n", position, true)
      local line = text:sub(position, (newline or #text + 1) - 1)
      position = (newline or #text) + 1
      return line
    end
    local chunk = text:sub(position, position + what - 1)
    position = position + #chunk
    return chunk
  end
  return stream
end

--- A complete `env` for `loglens.cli.main`.
-- @param opts table|nil `files` (path -> text), `stdin` (text), `env` (environment variables),
--   `tty` (boolean), `size` ({ columns, rows }), `now` (epoch seconds)
-- @return table env
-- @return table probe `{ fs, stdout(), stderr(), sleeps, clock() }` for assertions
function M.env(opts)
  opts = opts or {}
  local fs = M.fs(opts.files)
  local out, err, sleeps = {}, {}, {}
  local now = 0
  local variables = opts.env or {}
  local function sink(parts)
    return {
      write = function(self, text)
        parts[#parts + 1] = text
        return self
      end,
      flush = function() end,
    }
  end
  local env = {
    stdout = sink(out),
    stderr = sink(err),
    stdin = opts.stdin and M.stdin(opts.stdin) or nil,
    open = fs.open,
    getenv = function(name)
      return variables[name]
    end,
    now = function()
      return opts.now or 1794400000
    end,
    clock = function()
      return now
    end,
    sleep = function(seconds)
      sleeps[#sleeps + 1] = seconds
      now = now + seconds
    end,
  }
  if opts.tty ~= nil then
    env.is_tty = function()
      return opts.tty
    end
  end
  if opts.size then
    env.terminal_size = function()
      return opts.size[1], opts.size[2]
    end
  end
  return env, {
    fs = fs,
    sleeps = sleeps,
    stdout = function()
      return table.concat(out)
    end,
    stderr = function()
      return table.concat(err)
    end,
  }
end

return M
