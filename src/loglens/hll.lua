--- Distinct counting in bounded memory: HyperLogLog plus an exact-then-estimate counter.
--
-- `new` is a HyperLogLog sketch (Flajolet et al., 2007) with 2^p registers and a 64-bit hash
-- (FNV-1a with a murmur3 finalizer). The estimate uses the improved estimator of Otmar Ertl
-- ("New cardinality estimation algorithms for HyperLogLog sketches", 2017), which needs no bias
-- tables and is accurate from tiny to huge cardinalities. The standard error is about
-- 1.04 / sqrt(2^p): 1.6 % for the default p = 12 (4096 registers, roughly 64 KiB in Lua).
--
-- `counter` is what loglens uses for unique addresses: exact (a set) while the number of
-- distinct values stays under a limit, then it folds the set into a sketch and keeps going with
-- bounded memory.
-- @module loglens.hll
local M = {}

local byte = string.byte
local floor, log, sqrt, huge = math.floor, math.log, math.sqrt, math.huge

M.DEFAULT_PRECISION = 12

local FNV_OFFSET = 0xcbf29ce484222325
local FNV_PRIME = 0x100000001b3

--- 64-bit string hash (FNV-1a followed by the murmur3 64-bit finalizer).
-- @param text string
-- @return number a Lua integer (may be negative: only the bit pattern matters)
function M.hash(text)
  local h = FNV_OFFSET
  for i = 1, #text do
    h = (h ~ byte(text, i)) * FNV_PRIME
  end
  h = h ~ (h >> 33)
  h = h * 0xff51afd7ed558ccd
  h = h ~ (h >> 33)
  h = h * 0xc4ceb9fe1a85ec53
  h = h ~ (h >> 33)
  return h
end

-- Leading zero bits of a non-zero 64-bit integer.
local function leading_zeros(w)
  local n = 0
  while w > 0 do
    w = w << 1
    n = n + 1
  end
  return n
end

local function sigma(x)
  if x == 1 then
    return huge
  end
  local y, z = 1, x
  while true do
    x = x * x
    local previous = z
    z = z + x * y
    y = y + y
    if z == previous then
      return z
    end
  end
end

local function tau(x)
  if x == 0 or x == 1 then
    return 0
  end
  local y, z = 1, 1 - x
  while true do
    x = sqrt(x)
    local previous = z
    y = y * 0.5
    z = z - (1 - x) ^ 2 * y
    if z == previous then
      return z / 3
    end
  end
end

local Sketch = {}
Sketch.__index = Sketch

--- Creates a HyperLogLog sketch.
-- @param precision number|nil register index bits, 4..16 (default 12)
-- @return table
function M.new(precision)
  precision = precision or M.DEFAULT_PRECISION
  if math.type(precision) ~= "integer" or precision < 4 or precision > 16 then
    error("hll precision must be an integer between 4 and 16", 2)
  end
  local registers = {}
  for i = 1, 1 << precision do
    registers[i] = 0
  end
  return setmetatable({ p = precision, m = 1 << precision, registers = registers }, Sketch)
end

--- Adds a value (strings; other values are converted with `tostring`).
-- @param value string
function Sketch:add(value)
  local h = M.hash(type(value) == "string" and value or tostring(value))
  local p = self.p
  local index = (h >> (64 - p)) + 1
  local rest = h << p
  local rank = rest == 0 and (64 - p + 1) or (leading_zeros(rest) + 1)
  if rank > self.registers[index] then
    self.registers[index] = rank
  end
end

--- Estimated number of distinct values added so far.
-- @return number integer estimate
function Sketch:count()
  local m, q = self.m, 64 - self.p
  local counts = {}
  for k = 0, q + 1 do
    counts[k] = 0
  end
  for i = 1, m do
    local r = self.registers[i]
    counts[r] = counts[r] + 1
  end
  local z = m * tau(1 - counts[q + 1] / m)
  for k = q, 1, -1 do
    z = 0.5 * (z + counts[k])
  end
  z = z + m * sigma(counts[0] / m)
  return floor(m * m / (2 * log(2) * z) + 0.5)
end

--- Merges another sketch of the same precision into this one (set union).
-- @param other table
function Sketch:merge(other)
  if other.p ~= self.p then
    error("cannot merge sketches of different precision", 2)
  end
  for i = 1, self.m do
    if other.registers[i] > self.registers[i] then
      self.registers[i] = other.registers[i]
    end
  end
end

local Counter = {}
Counter.__index = Counter

--- Creates a counter that is exact up to `limit` distinct values and an estimate beyond.
-- @param limit number maximum number of distinct values kept exactly
-- @param precision number|nil sketch precision after the switch (default 12)
-- @return table
function M.counter(limit, precision)
  return setmetatable({ limit = limit, precision = precision, items = {}, n = 0 }, Counter)
end

--- Adds a value.
-- @param value string
function Counter:add(value)
  local sketch = self.sketch
  if sketch then
    sketch:add(value)
    return
  end
  if self.items[value] then
    return
  end
  self.items[value] = true
  self.n = self.n + 1
  if self.n > self.limit then
    sketch = M.new(self.precision)
    for item in pairs(self.items) do
      sketch:add(item)
    end
    self.sketch, self.items = sketch, nil
  end
end

--- Number of distinct values (exact until the limit is exceeded, then an estimate).
-- @return number
function Counter:count()
  if self.sketch then
    return self.sketch:count()
  end
  return self.n
end

--- Whether `count` is still exact.
-- @return boolean
function Counter:is_exact()
  return self.sketch == nil
end

return M
