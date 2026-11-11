local t = require("spec.support")
local topk = require("loglens.topk")
local hll = require("loglens.hll")
local histogram = require("loglens.histogram")
local lcg = require("tools.lcg")

---------------------------------------------------------------------------------------------
-- Space-Saving top-K
---------------------------------------------------------------------------------------------

-- Draws `n` keys from a Zipf(s) distribution over `distinct` keys using the seeded generator.
local function zipf_stream(rng, distinct, s, n)
  local cumulative, total = {}, 0
  for i = 1, distinct do
    total = total + 1 / i ^ s
    cumulative[i] = total
  end
  local stream = {}
  for k = 1, n do
    local target = rng:float() * total
    local lo, hi = 1, distinct
    while lo < hi do
      local mid = (lo + hi) // 2
      if cumulative[mid] >= target then
        hi = mid
      else
        lo = mid + 1
      end
    end
    stream[k] = "k" .. lo
  end
  return stream
end

t.describe("topk", function()
  t.it("counts exactly while under capacity", function()
    local sketch = topk.new(10)
    for _, key in ipairs({ "a", "b", "a", "c", "a", "b" }) do
      sketch:add(key)
    end
    local top = sketch:top()
    t.eq(#top, 3)
    t.eq({ top[1].key, top[1].count, top[1].over }, { "a", 3, 0 })
    t.eq({ top[2].key, top[2].count }, { "b", 2 })
    t.eq({ top[3].key, top[3].count }, { "c", 1 })
    t.eq(sketch.total, 6)
    t.eq(sketch:floor_count(), 0)
  end)

  t.it("orders ties by key and honours the limit", function()
    local sketch = topk.new(10)
    for _, key in ipairs({ "d", "b", "c", "a" }) do
      sketch:add(key)
    end
    local keys = {}
    for i, entry in ipairs(sketch:top(3)) do
      keys[i] = entry.key
    end
    t.eq(keys, { "a", "b", "c" })
  end)

  t.it("evicts the minimum and records the over-estimate", function()
    local sketch = topk.new(2)
    sketch:add("a")
    sketch:add("a")
    sketch:add("b")
    local entry, fresh = sketch:add("c")
    t.is_true(fresh)
    t.eq({ entry.key, entry.count, entry.over }, { "c", 2, 1 })
    t.is_nil(sketch:get("b"))
    t.eq(sketch:len(), 2)
    t.eq(sketch:floor_count(), 2)
  end)

  t.it("keeps caller payload on the entry and flags new entries", function()
    local sketch = topk.new(2)
    local entry, fresh = sketch:add("a")
    t.is_true(fresh)
    entry.bytes = 10
    local again, fresh_again = sketch:add("a")
    t.is_false(fresh_again)
    t.ok(again == entry)
    t.eq(again.bytes, 10)
  end)

  t.it("supports weights", function()
    local sketch = topk.new(3)
    sketch:add("a", 5)
    sketch:add("b", 2)
    sketch:add("a", 1)
    t.eq(sketch:top()[1].count, 6)
    t.eq(sketch.total, 8)
  end)

  t.it("validates the capacity", function()
    t.raises(function()
      topk.new(0)
    end, "positive")
    t.raises(function()
      topk.new("x")
    end, "positive")
    local single = topk.new(1)
    single:add("a")
    single:add("b")
    t.eq(single:top()[1].key, "b")
    t.eq(single:top()[1].count, 2)
  end)

  t.it("keeps the heap invariant under random updates", function()
    local rng = lcg.new(11)
    local sketch = topk.new(64)
    for _ = 1, 20000 do
      sketch:add("k" .. rng:range(1, 300))
    end
    for i = 2, sketch.n do
      t.ok(sketch.heap[i // 2].count <= sketch.heap[i].count)
    end
    for i = 1, sketch.n do
      t.eq(sketch.heap[i].pos, i)
      t.ok(sketch.index[sketch.heap[i].key] == sketch.heap[i])
    end
  end)

  t.it("meets the Space-Saving guarantees on a Zipf stream", function()
    local rng = lcg.new(424242)
    local n, capacity = 100000, 500
    local stream = zipf_stream(rng, 20000, 1.1, n)
    local truth = {}
    local sketch = topk.new(capacity)
    for _, key in ipairs(stream) do
      truth[key] = (truth[key] or 0) + 1
      sketch:add(key)
    end
    t.eq(sketch:len(), capacity)
    for _, entry in ipairs(sketch:top()) do
      local true_count = truth[entry.key]
      t.ok(entry.count - entry.over <= true_count, "lower bound for " .. entry.key)
      t.ok(true_count <= entry.count, "upper bound for " .. entry.key)
    end
    for key, true_count in pairs(truth) do
      if true_count > n / capacity then
        t.ok(sketch:get(key), key .. " is a heavy hitter and must be tracked")
      end
    end
    local ranked = {}
    for key, count in pairs(truth) do
      ranked[#ranked + 1] = { key = key, count = count }
    end
    table.sort(ranked, function(a, b)
      if a.count ~= b.count then
        return a.count > b.count
      end
      return a.key < b.key
    end)
    local reported = sketch:top(20)
    local reported_keys = {}
    for _, entry in ipairs(reported) do
      reported_keys[entry.key] = true
    end
    for i = 1, 10 do
      t.ok(reported_keys[ranked[i].key], "true #" .. i .. " must be in the reported top 20")
    end
    t.eq(reported[1].key, ranked[1].key)
  end)

  t.it("stays bounded under a flood of unique keys", function()
    local rng = lcg.new(5)
    local sketch = topk.new(1000)
    collectgarbage("collect")
    local before = collectgarbage("count")
    local started = os.clock()
    for i = 1, 100000 do
      sketch:add("/random/" .. rng:next() .. "/" .. i)
    end
    local elapsed = os.clock() - started
    collectgarbage("collect")
    t.eq(sketch:len(), 1000)
    t.eq(sketch.total, 100000)
    t.lt(collectgarbage("count") - before, 2048, "memory must not grow with distinct keys (KiB)")
    t.lt(elapsed, 6)
  end)

  t.it("does not let a flood displace a real heavy hitter", function()
    local rng = lcg.new(8)
    local sketch = topk.new(100)
    for i = 1, 20000 do
      if i % 4 == 0 then
        sketch:add("/popular")
      else
        sketch:add("/junk/" .. rng:next())
      end
    end
    t.eq(sketch:top(1)[1].key, "/popular")
    t.ge(sketch:top(1)[1].count, 5000)
  end)
end)

---------------------------------------------------------------------------------------------
-- HyperLogLog
---------------------------------------------------------------------------------------------

local function distinct_keys(prefix, n, offset)
  local keys = {}
  for i = 1, n do
    keys[i] = prefix .. (i + (offset or 0))
  end
  return keys
end

t.describe("hll.hash", function()
  t.it("is deterministic and avalanches", function()
    t.eq(hll.hash("203.0.113.9"), hll.hash("203.0.113.9"))
    t.neq(hll.hash("a"), hll.hash("b"))
    t.neq(hll.hash(""), hll.hash(" "))
    local flipped, samples = 0, 500
    for i = 1, samples do
      local a, b = hll.hash("10.0.0." .. i), hll.hash("10.0.0." .. i .. "x")
      local diff = a ~ b
      for bit = 0, 63 do
        if (diff >> bit) & 1 == 1 then
          flipped = flipped + 1
        end
      end
    end
    local average = flipped / samples
    t.ok(average > 28 and average < 36, "average flipped bits " .. average)
  end)
end)

t.describe("hll sketch", function()
  t.it("rejects invalid precision", function()
    t.raises(function()
      hll.new(3)
    end, "precision")
    t.raises(function()
      hll.new(17)
    end, "precision")
    t.raises(function()
      hll.new(12.5)
    end, "precision")
  end)

  t.it("starts at zero", function()
    t.eq(hll.new():count(), 0)
  end)

  t.it("is within three standard errors across six orders of magnitude (p = 12)", function()
    local standard_error = 1.04 / math.sqrt(4096)
    for _, n in ipairs({ 1, 5, 50, 500, 2000, 10000, 40000, 100000, 400000 }) do
      local sketch = hll.new(12)
      for _, key in ipairs(distinct_keys("10.", n)) do
        sketch:add(key)
      end
      local estimate = sketch:count()
      local error_ratio = math.abs(estimate - n) / n
      t.ok(error_ratio <= math.max(3 * standard_error, 1 / n),
        string.format("n=%d estimate=%d error=%.2f%%", n, estimate, error_ratio * 100))
    end
  end)

  t.it("ignores duplicates", function()
    local sketch = hll.new(10)
    for _ = 1, 20 do
      for _, key in ipairs(distinct_keys("host-", 300)) do
        sketch:add(key)
      end
    end
    t.near(sketch:count(), 300, 300 * 3 * 1.04 / math.sqrt(1024))
  end)

  t.it("merges sketches as a set union", function()
    local a, b = hll.new(12), hll.new(12)
    for _, key in ipairs(distinct_keys("u", 30000)) do
      a:add(key)
    end
    for _, key in ipairs(distinct_keys("u", 30000, 15000)) do
      b:add(key)
    end
    a:merge(b)
    t.near(a:count(), 45000, 45000 * 3 * 1.04 / 64)
    t.raises(function()
      a:merge(hll.new(10))
    end, "precision")
  end)

  t.it("tracks lower precision with proportionally larger error", function()
    local sketch = hll.new(8)
    for _, key in ipairs(distinct_keys("q", 20000)) do
      sketch:add(key)
    end
    t.near(sketch:count(), 20000, 20000 * 3 * 1.04 / 16)
  end)
end)

t.describe("hll counter (exact, then estimate)", function()
  t.it("is exact up to the limit", function()
    local counter = hll.counter(1000, 12)
    for _, key in ipairs(distinct_keys("a", 1000)) do
      counter:add(key)
      counter:add(key)
    end
    t.eq(counter:count(), 1000)
    t.is_true(counter:is_exact())
  end)

  t.it("switches to an estimate beyond the limit and frees the set", function()
    local counter = hll.counter(1000, 12)
    for _, key in ipairs(distinct_keys("a", 5000)) do
      counter:add(key)
    end
    t.is_false(counter:is_exact())
    t.is_nil(counter.items)
    t.near(counter:count(), 5000, 5000 * 3 * 1.04 / 64)
    for _, key in ipairs(distinct_keys("a", 5000)) do
      counter:add(key)
    end
    t.near(counter:count(), 5000, 5000 * 3 * 1.04 / 64)
  end)

  t.it("handles a large stream with the default exact limit", function()
    local rng = lcg.new(31)
    local counter = hll.counter(10000, 12)
    local truth, distinct = {}, 0
    for _ = 1, 60000 do
      local key = "192.0." .. rng:range(0, 255) .. "." .. rng:range(0, 255)
      if not truth[key] then
        truth[key] = true
        distinct = distinct + 1
      end
      counter:add(key)
    end
    t.is_false(counter:is_exact())
    t.near(counter:count(), distinct, distinct * 3 * 1.04 / 64)
  end)
end)

---------------------------------------------------------------------------------------------
-- Histogram
---------------------------------------------------------------------------------------------

local function exact_quantile(sorted, q)
  local rank = math.max(1, math.ceil(q * #sorted))
  return sorted[rank]
end

t.describe("histogram", function()
  t.it("is empty at first", function()
    local h = histogram.new()
    t.eq(h:count(), 0)
    t.is_nil(h:quantile(0.5))
    t.is_nil(h:mean())
    t.is_nil(h:min())
    t.is_nil(h:max())
  end)

  t.it("ignores invalid samples", function()
    local h = histogram.new()
    t.is_false(h:add(-1))
    t.is_false(h:add(0 / 0))
    t.is_false(h:add(math.huge))
    t.is_false(h:add("1"))
    t.is_true(h:add(0.25))
    t.eq(h:count(), 1)
  end)

  t.it("reports exact count, sum, min and max", function()
    local h = histogram.new()
    for _, v in ipairs({ 0.2, 0.4, 0.6 }) do
      h:add(v)
    end
    t.near(h:mean(), 0.4, 1e-12)
    t.eq(h:min(), 0.2)
    t.eq(h:max(), 0.6)
    t.eq(h:quantile(1), 0.6)
    t.eq(h:quantile(0), 0.2)
  end)

  t.it("handles a single value and constant data within the accuracy bound", function()
    local h = histogram.new()
    h:add(0.123)
    t.eq(h:quantile(0.5), 0.123, "clamped to the observed range")
    local c = histogram.new()
    for _ = 1, 1000 do
      c:add(0.5)
    end
    for _, q in ipairs({ 0.1, 0.5, 0.99 }) do
      t.near(c:quantile(q), 0.5, 0.5 * 0.01)
    end
  end)

  t.it("counts sub-resolution values as zero", function()
    local h = histogram.new()
    for _ = 1, 90 do
      h:add(0)
    end
    for _ = 1, 10 do
      h:add(1.5)
    end
    t.eq(h:quantile(0.5), 0)
    t.eq(h:quantile(0.9), 0)
    t.near(h:quantile(0.95), 1.5, 0.015)
  end)

  t.it("clamps values outside the configured range", function()
    local h = histogram.new({ min_value = 0.001, max_value = 10 })
    h:add(1e6)
    h:add(0.5)
    t.eq(h:max(), 1e6)
    t.eq(h:quantile(1), 1e6)
    t.ok(h:quantile(0.99) <= 1e6)
  end)

  t.it("keeps percentile error within the relative accuracy on log-normal latencies", function()
    local rng = lcg.new(777)
    local h = histogram.new({ accuracy = 0.01 })
    local values = {}
    for i = 1, 30000 do
      values[i] = rng:lognormal(0.05, 1.3)
      h:add(values[i])
    end
    table.sort(values)
    for _, q in ipairs({ 0.01, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 0.999 }) do
      local exact = exact_quantile(values, q)
      local estimate = h:quantile(q)
      t.ok(math.abs(estimate - exact) / exact <= 0.01 + 1e-9,
        string.format("q=%s exact=%g estimate=%g", q, exact, estimate))
    end
  end)

  t.it("keeps error within a looser configured accuracy on bimodal data", function()
    local rng = lcg.new(9)
    local h = histogram.new({ accuracy = 0.05 })
    local values = {}
    for i = 1, 20000 do
      values[i] = rng:chance(0.8) and rng:lognormal(0.01, 0.3) or rng:lognormal(2, 0.4)
      h:add(values[i])
    end
    table.sort(values)
    for _, q in ipairs({ 0.5, 0.79, 0.81, 0.9, 0.99 }) do
      local exact = exact_quantile(values, q)
      t.ok(math.abs(h:quantile(q) - exact) / exact <= 0.05 + 1e-9, "q=" .. q)
    end
  end)

  t.it("uses constant memory", function()
    local h = histogram.new()
    t.lt(h.size, 1400)
    local rng = lcg.new(3)
    for _ = 1, 100000 do
      h:add(rng:float())
    end
    t.lt(h.size, 1400)
    t.eq(h:count(), 100000)
  end)

  t.it("validates its configuration", function()
    t.raises(function()
      histogram.new({ accuracy = 0 })
    end, "accuracy")
    t.raises(function()
      histogram.new({ accuracy = 1 })
    end, "accuracy")
  end)
end)
