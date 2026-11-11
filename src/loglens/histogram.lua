--- Fixed log-bucket histogram for latency percentiles in constant memory.
--
-- Buckets grow geometrically by gamma = (1 + a) / (1 - a), so every reported quantile is within
-- a relative error `a` of the true value (the DDSketch mapping; default a = 1 %). The bucket
-- array is allocated once: with the defaults (1 microsecond to 100 000 seconds) that is about
-- 1,270 counters regardless of how many samples arrive. `count`, `sum`, `min` and `max` are
-- exact.
-- @module loglens.histogram
local M = {}

local ceil, log, huge = math.ceil, math.log, math.huge

local Histogram = {}
Histogram.__index = Histogram

--- Creates a histogram.
-- @param opts table|nil `{ accuracy = 0.01, min_value = 1e-6, max_value = 1e5 }`; samples below
--   `min_value` are counted as zero, samples above `max_value` land in the last bucket
-- @return table
function M.new(opts)
  opts = opts or {}
  local accuracy = opts.accuracy or 0.01
  if accuracy <= 0 or accuracy >= 1 then
    error("histogram accuracy must be between 0 and 1", 2)
  end
  local min_value = opts.min_value or 1e-6
  local max_value = opts.max_value or 1e5
  local gamma = (1 + accuracy) / (1 - accuracy)
  local log_gamma = log(gamma)
  local size = ceil(log(max_value / min_value) / log_gamma) + 1
  local buckets = {}
  for i = 1, size do
    buckets[i] = 0
  end
  return setmetatable({
    gamma = gamma,
    log_gamma = log_gamma,
    min_value = min_value,
    size = size,
    buckets = buckets,
    zeros = 0,
    n = 0,
    total = 0,
    low = huge,
    high = -huge,
  }, Histogram)
end

--- Adds a sample. Negative, NaN and infinite values are ignored.
-- @param value number
-- @return boolean whether the sample was accepted
function Histogram:add(value)
  if type(value) ~= "number" or value ~= value or value < 0 or value == huge then
    return false
  end
  self.n = self.n + 1
  self.total = self.total + value
  if value < self.low then
    self.low = value
  end
  if value > self.high then
    self.high = value
  end
  if value < self.min_value then
    self.zeros = self.zeros + 1
    return true
  end
  local index = ceil(log(value / self.min_value) / self.log_gamma) + 1
  if index < 1 then
    index = 1
  elseif index > self.size then
    index = self.size
  end
  self.buckets[index] = self.buckets[index] + 1
  return true
end

--- Number of accepted samples.
-- @return number
function Histogram:count()
  return self.n
end

--- Arithmetic mean (exact).
-- @return number|nil nil when empty
function Histogram:mean()
  if self.n == 0 then
    return nil
  end
  return self.total / self.n
end

--- Smallest sample (exact).
-- @return number|nil
function Histogram:min()
  return self.n > 0 and self.low or nil
end

--- Largest sample (exact).
-- @return number|nil
function Histogram:max()
  return self.n > 0 and self.high or nil
end

--- Nearest-rank quantile, accurate to the configured relative error.
-- @param q number 0..1 (0.99 is p99)
-- @return number|nil nil when empty
function Histogram:quantile(q)
  if self.n == 0 then
    return nil
  end
  if q <= 0 then
    return self.low
  elseif q >= 1 then
    return self.high
  end
  local rank = ceil(q * self.n)
  if rank < 1 then
    rank = 1
  end
  local seen = self.zeros
  if rank <= seen then
    return 0
  end
  local buckets = self.buckets
  for i = 1, self.size do
    local c = buckets[i]
    if c > 0 then
      seen = seen + c
      if seen >= rank then
        local upper = self.min_value * self.gamma ^ (i - 1)
        local value = 2 * upper / (self.gamma + 1)
        if value < self.low then
          return self.low
        elseif value > self.high then
          return self.high
        end
        return value
      end
    end
  end
  return self.high
end

return M
