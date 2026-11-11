--- Space-Saving heavy-hitter sketch (Metwally, Agrawal and El Abbadi, 2005).
--
-- Tracks the most frequent keys of an unbounded stream in memory proportional to `capacity`,
-- no matter how many distinct keys are seen. This is what stops a flood of random URLs, user
-- agents or addresses from exhausting memory.
--
-- Guarantees for a stream of N weighted observations and a capacity of C:
--   * every key whose true count exceeds N / C is tracked;
--   * for a tracked key, `count - over <= true count <= count` (`over` is the over-estimate bound);
--   * keys that are never evicted are counted exactly (`over == 0`).
--
-- Entries live in a binary min-heap ordered by `count`, so an update costs O(log C). `add`
-- returns the entry table itself: callers may attach payload fields (they are discarded
-- together with the entry when a key is evicted; `add`'s second result says when to initialise
-- them).
-- @module loglens.topk
local M = {}

local sort = table.sort

local TopK = {}
TopK.__index = TopK

--- Creates a sketch.
-- @param capacity number maximum number of tracked keys (>= 1)
-- @return table
function M.new(capacity)
  if type(capacity) ~= "number" or capacity < 1 then
    error("topk capacity must be a positive number", 2)
  end
  return setmetatable({
    capacity = math.floor(capacity),
    n = 0,
    total = 0,
    heap = {},
    index = {},
  }, TopK)
end

local function sift_down(heap, n, i)
  local entry = heap[i]
  local count = entry.count
  while true do
    local child = 2 * i
    if child > n then
      break
    end
    if child < n and heap[child + 1].count < heap[child].count then
      child = child + 1
    end
    local candidate = heap[child]
    if candidate.count >= count then
      break
    end
    heap[i] = candidate
    candidate.pos = i
    i = child
  end
  heap[i] = entry
  entry.pos = i
end

local function sift_up(heap, i)
  local entry = heap[i]
  local count = entry.count
  while i > 1 do
    local parent = i // 2
    local candidate = heap[parent]
    if candidate.count <= count then
      break
    end
    heap[i] = candidate
    candidate.pos = i
    i = parent
  end
  heap[i] = entry
  entry.pos = i
end

--- Records `weight` occurrences of `key`.
-- @param key string|number
-- @param weight number|nil positive amount (default 1)
-- @return table entry with `key`, `count`, `over`, `pos` plus any caller-owned payload
-- @return boolean true when the entry is new (first sighting or replaced an evicted key)
function TopK:add(key, weight)
  weight = weight or 1
  self.total = self.total + weight
  local entry = self.index[key]
  if entry then
    entry.count = entry.count + weight
    sift_down(self.heap, self.n, entry.pos)
    return entry, false
  end
  if self.n < self.capacity then
    self.n = self.n + 1
    entry = { key = key, count = weight, over = 0, pos = self.n }
    self.heap[self.n] = entry
    self.index[key] = entry
    sift_up(self.heap, self.n)
    return entry, true
  end
  local root = self.heap[1]
  self.index[root.key] = nil
  entry = { key = key, count = root.count + weight, over = root.count, pos = 1 }
  self.heap[1] = entry
  self.index[key] = entry
  sift_down(self.heap, self.n, 1)
  return entry, true
end

--- Looks up a tracked key.
-- @param key string|number
-- @return table|nil entry
function TopK:get(key)
  return self.index[key]
end

--- Number of tracked keys (never more than the capacity).
-- @return number
function TopK:len()
  return self.n
end

--- Smallest tracked count: an upper bound on the true count of any key that is not tracked.
-- @return number 0 while the sketch is not full
function TopK:floor_count()
  if self.n < self.capacity then
    return 0
  end
  return self.heap[1].count
end

--- Tracked entries ordered by descending count, then ascending key (deterministic).
-- @param limit number|nil keep only the first `limit` entries
-- @return table[] entries (shared with the sketch: treat as read-only)
function TopK:top(limit)
  local list = {}
  for i = 1, self.n do
    list[i] = self.heap[i]
  end
  sort(list, function(a, b)
    if a.count ~= b.count then
      return a.count > b.count
    end
    return a.key < b.key
  end)
  if limit and limit < #list then
    for i = #list, limit + 1, -1 do
      list[i] = nil
    end
  end
  return list
end

return M
