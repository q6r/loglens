local t = require("spec.support")
local fakes = require("spec.fakes")
local lcg = require("tools.lcg")
local lines = require("loglens.lines")

local function collect()
  local got = {}
  return got, function(line)
    got[#got + 1] = line
  end
end

local function split_all(chunks, max_bytes)
  local splitter = lines.splitter(max_bytes or 100)
  local got, emit = collect()
  for _, chunk in ipairs(chunks) do
    splitter:push(chunk, emit)
  end
  splitter:finish(emit)
  return got
end

t.describe("lines.splitter", function()
  t.it("splits on newlines and keeps empty lines", function()
    t.eq(split_all({ "a\nb\n\nc\n" }), { "a", "b", "", "c" })
    t.eq(split_all({ "\n\n" }), { "", "" })
  end)

  t.it("joins a line that spans chunks and delivers an unterminated last line", function()
    t.eq(split_all({ "he", "llo wor", "ld\nsec", "ond" }), { "hello world", "second" })
    t.eq(split_all({ "x" }), { "x" })
    t.eq(split_all({}), {})
    t.eq(split_all({ "", "ab\n", "" }), { "ab" })
  end)

  t.it("leaves carriage returns to the consumer", function()
    t.eq(split_all({ "a\r\nb\r\n" }), { "a\r", "b\r" })
  end)

  t.it("cuts an over-long line to max_bytes + 1 and discards the rest", function()
    local got = split_all({ string.rep("x", 30), string.rep("y", 30), "z\nshort\n" }, 40)
    t.eq(#got, 2)
    t.eq(#got[1], 41, "long enough to be recognised as too long, no longer")
    t.eq(got[1], string.rep("x", 30) .. string.rep("y", 11))
    t.eq(got[2], "short")
    t.eq(split_all({ string.rep("a", 41) .. "\n" }, 40)[1], string.rep("a", 41))
    t.eq(split_all({ string.rep("a", 40) .. "\n" }, 40)[1], string.rep("a", 40), "exactly at the limit is kept")
  end)

  t.it("keeps memory bounded however long a line is", function()
    local splitter = lines.splitter(64)
    local got, emit = collect()
    for _ = 1, 5000 do
      splitter:push(string.rep("z", 1000), emit)
    end
    t.eq(#got, 0)
    t.ge(splitter.size, 1)
    t.lt(splitter.size, 66)
    splitter:push("\nok\n", emit)
    t.eq(#got[1], 65)
    t.eq(got[2], "ok")
  end)

  t.it("forgets the incomplete line on reset", function()
    local splitter = lines.splitter(100)
    local got, emit = collect()
    splitter:push("partial", emit)
    splitter:reset()
    splitter:push("fresh\n", emit)
    t.eq(got, { "fresh" })
  end)

  t.it("gives the same lines however the text is cut into chunks (property)", function()
    local rng = lcg.new(99)
    local pieces = {}
    for i = 1, 60 do
      pieces[i] = string.rep(string.char(97 + i % 26), rng:range(0, 30)) .. (rng:chance(0.8) and "\n" or "")
    end
    local text = table.concat(pieces)
    local expected = split_all({ text }, 1000)
    for _ = 1, 200 do
      local chunks, position = {}, 1
      while position <= #text do
        local size = rng:range(1, 25)
        chunks[#chunks + 1] = text:sub(position, position + size - 1)
        position = position + size
      end
      t.eq(split_all(chunks, 1000), expected)
    end
  end)
end)

t.describe("lines.read_stream", function()
  t.it("emits every line of a stream, also across chunk sizes", function()
    local original = lines.CHUNK
    for _, size in ipairs({ 1, 3, 7, 4096 }) do
      lines.CHUNK = size
      local got, emit = collect()
      t.is_true(lines.read_stream(fakes.stdin("one\ntwo\n\nthree"), 100, emit))
      t.eq(got, { "one", "two", "", "three" })
    end
    lines.CHUNK = original
  end)

  t.it("reports a read error", function()
    local broken = {
      read = function()
        return nil, "Is a directory"
      end,
    }
    local ok, err = lines.read_stream(broken, 100, function() end)
    t.is_nil(ok)
    t.eq(err, "Is a directory")
  end)
end)
