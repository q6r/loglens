--- Deterministic pseudo-random numbers for reproducible fixtures and tests.
--
-- A 64-bit linear congruential generator (Knuth's MMIX constants). Lua integers wrap on overflow,
-- so the sequence is identical on every platform and every Lua 5.3/5.4 build.
-- @module tools.lcg
local M = {}

local Rng = {}
Rng.__index = Rng

--- Creates a generator.
-- @param seed number|nil integer seed (default 1)
-- @return table
function M.new(seed)
  return setmetatable({ state = seed or 1 }, Rng)
end

--- Next raw value, uniformly distributed in [0, 2^31).
function Rng:next()
  self.state = self.state * 6364136223846793005 + 1442695040888963407
  return self.state >> 33
end

--- Uniform float in [0, 1).
function Rng:float()
  return self:next() / 2147483648
end

--- Uniform integer in [lo, hi].
function Rng:range(lo, hi)
  return lo + self:next() % (hi - lo + 1)
end

--- True with probability `p`.
function Rng:chance(p)
  return self:float() < p
end

--- Uniformly picks one element of a non-empty array.
function Rng:pick(list)
  return list[self:next() % #list + 1]
end

--- Picks from `{ { item, weight }, ... }` proportionally to the weights.
function Rng:weighted(entries)
  local total = 0
  for _, entry in ipairs(entries) do
    total = total + entry[2]
  end
  local target = self:float() * total
  for _, entry in ipairs(entries) do
    target = target - entry[2]
    if target < 0 then
      return entry[1]
    end
  end
  return entries[#entries][1]
end

--- Approximately log-normal positive number with the given median and spread (sigma of the log).
function Rng:lognormal(median, sigma)
  local u1 = math.max(self:float(), 1e-12)
  local u2 = self:float()
  local normal = math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)
  return median * math.exp(sigma * normal)
end

return M
