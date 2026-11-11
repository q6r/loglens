--- Sources for the live view: a file that keeps growing, or a stream such as standard input.
--
-- Both kinds answer `poll(emit, keep_going)`: they call `emit(line)` for every new line and return
-- a status. `keep_going` (optional) is asked after every chunk and ends the poll early when it
-- returns false, so a huge backlog never starves the redraw loop; a poll always reads at least one
-- chunk, so progress is guaranteed.
--
-- Statuses: `"tailing"` (all well), `"rotated"` (the file shrank or was replaced and is read from
-- the start), `"waiting"` (the file does not exist yet), `"eof"` (the stream ended) and `"error"`
-- (the second return value says why).
-- @module loglens.tail
local lines = require("loglens.lines")

local M = {}

local min = math.min
local sub = string.sub

local FINGERPRINT_BYTES = 64

local FileSource = {}
FileSource.__index = FileSource

--- Follows a file. Every poll opens it, reads what was appended since the previous poll and closes
-- it again: no handle stays open, so rotation or deletion by another program is never blocked
-- (which matters on Windows) and a replaced file is noticed by looking at the path, not at an old
-- handle. A file counts as replaced when it is smaller than what was already read, when its first
-- bytes changed, or when it disappeared and came back.
-- @param path string
-- @param opts table|nil `{ open = io.open, max_line_bytes = 65536, new_only = false }`;
--   `new_only` starts at the current end of the file instead of its beginning
-- @return table source
function M.file(path, opts)
  opts = opts or {}
  return setmetatable({
    path = path,
    open = opts.open or io.open,
    new_only = opts.new_only or false,
    splitter = lines.splitter(opts.max_line_bytes or 65536),
    offset = nil,
    head = nil,
    missing = false,
  }, FileSource)
end

local function same_prefix(a, b)
  local n = min(#a, #b)
  return sub(a, 1, n) == sub(b, 1, n)
end

--- Reads what was appended since the previous call.
-- @param emit function called with every complete line
-- @param keep_going function|nil returns false to stop after the current chunk
-- @return string status
-- @return string|nil message for status `"error"`
function FileSource:poll(emit, keep_going)
  local file = self.open(self.path, "rb")
  if not file then
    self.missing = true
    return "waiting"
  end
  local size, seek_error = file:seek("end")
  if not size then
    file:close()
    return "error", seek_error
  end
  local head
  if size > 0 then
    file:seek("set", 0)
    head = file:read(FINGERPRINT_BYTES)
  end

  local status = "tailing"
  if self.offset == nil then
    self.offset = self.new_only and size or 0
  elseif self.missing or size < self.offset
      or (self.head and head and not same_prefix(head, self.head)) then
    self.offset, self.head, status = 0, nil, "rotated"
    self.splitter:reset()
  end
  self.missing = false
  if head and (not self.head or #head > #self.head) then
    self.head = head
  end

  if size > self.offset then
    file:seek("set", self.offset)
    while true do
      local chunk, err = file:read(lines.CHUNK)
      if not chunk then
        file:close()
        return err and "error" or status, err
      end
      self.offset = self.offset + #chunk
      self.splitter:push(chunk, emit)
      if keep_going and not keep_going() then
        break
      end
    end
  end
  file:close()
  return status
end

local StreamSource = {}
StreamSource.__index = StreamSource

--- Reads a stream line by line. Pure Lua cannot poll a pipe, so `poll` blocks until a line arrives
-- (it then keeps reading while `keep_going` allows and data is available to `read`).
-- @param stream table anything with a Lua-file-like `read("l")`, such as `io.stdin`
-- @return table source
function M.stream(stream)
  return setmetatable({ stream = stream }, StreamSource)
end

--- Reads lines until `keep_going` says stop or the stream ends.
-- @param emit function called with every line
-- @param keep_going function|nil
-- @return string status `"tailing"` or `"eof"` (or `"error"` plus a message)
function StreamSource:poll(emit, keep_going)
  while true do
    local line, err = self.stream:read("l")
    if not line then
      if err then
        return "error", err
      end
      return "eof"
    end
    emit(line)
    if keep_going and not keep_going() then
      return "tailing"
    end
  end
end

return M
