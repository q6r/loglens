--- Bounded-memory line splitting for streams that may contain arbitrarily long lines.
--
-- `io.lines` and `file:read("l")` allocate a whole line before the caller can look at it, so one
-- gigantic "line" (a binary file, a log without newlines) could exhaust memory. The splitter below
-- works on fixed-size chunks and keeps at most `max_bytes + 1` bytes of any line.
-- @module loglens.lines
local M = {}

local concat = table.concat
local find, sub = string.find, string.sub

--- Chunk size used when reading streams.
M.CHUNK = 65536

local Splitter = {}
Splitter.__index = Splitter

--- Creates a splitter.
-- @param max_bytes number longest line kept. A longer line is delivered cut to `max_bytes + 1`
--   bytes, so the consumer can still tell that it was too long; the rest is never stored.
-- @return table splitter with `push(chunk, emit)`, `finish(emit)` and `reset()`
function M.splitter(max_bytes)
  return setmetatable({ max = max_bytes, parts = {}, size = 0 }, Splitter)
end

-- Appends a fragment of an unfinished line, keeping at most `max + 1` bytes in total.
function Splitter:append(fragment)
  local room = self.max + 1 - self.size
  if room <= 0 or fragment == "" then
    return
  end
  if #fragment > room then
    fragment = sub(fragment, 1, room)
  end
  self.parts[#self.parts + 1] = fragment
  self.size = self.size + #fragment
end

-- The finished line: what was carried over plus the text before the newline.
function Splitter:take(tail)
  if self.size == 0 then
    return #tail > self.max + 1 and sub(tail, 1, self.max + 1) or tail
  end
  self:append(tail)
  local line = concat(self.parts)
  self.parts, self.size = {}, 0
  return line
end

--- Adds a chunk of the stream and calls `emit(line)` for every complete line (without its "\n").
-- An incomplete last line is kept for the next chunk.
-- @param chunk string
-- @param emit function
function Splitter:push(chunk, emit)
  local pos = 1
  while true do
    local newline = find(chunk, "\n", pos, true)
    if not newline then
      self:append(sub(chunk, pos))
      return
    end
    emit(self:take(sub(chunk, pos, newline - 1)))
    pos = newline + 1
  end
end

--- Delivers the unterminated last line, if there is one.
-- @param emit function
function Splitter:finish(emit)
  if self.size > 0 then
    local line = concat(self.parts)
    self.parts, self.size = {}, 0
    emit(line)
  end
end

--- Forgets the incomplete line (used when a followed file was replaced).
function Splitter:reset()
  self.parts, self.size = {}, 0
end

--- Reads a whole stream and calls `emit(line)` for each of its lines.
-- @param stream table anything with a Lua-file-like `read(n)` (a file, `io.stdin`)
-- @param max_bytes number see `splitter`
-- @param emit function
-- @return boolean|nil true when the end of the stream was reached
-- @return string|nil error message when reading failed
function M.read_stream(stream, max_bytes, emit)
  local splitter = M.splitter(max_bytes)
  while true do
    local chunk, err = stream:read(M.CHUNK)
    if not chunk then
      if err then
        return nil, err
      end
      break
    end
    splitter:push(chunk, emit)
  end
  splitter:finish(emit)
  return true
end

return M
