local t = require("spec.support")
local fakes = require("spec.fakes")
local lines = require("loglens.lines")
local tail = require("loglens.tail")

local function poll(source, keep_going)
  local got = {}
  local status, err = source:poll(function(line)
    got[#got + 1] = line
  end, keep_going)
  return got, status, err
end

t.describe("tail.file", function()
  t.it("waits for a file that does not exist yet, then reads it from the start", function()
    local fs = fakes.fs()
    local source = tail.file("a.log", { open = fs.open })
    local got, status = poll(source)
    t.eq(got, {})
    t.eq(status, "waiting")
    fs.files["a.log"] = "one\ntwo\n"
    got, status = poll(source)
    t.eq(got, { "one", "two" })
    t.eq(status, "tailing", "the first appearance is not a rotation")
  end)

  t.it("returns only what was appended since the previous poll", function()
    local fs = fakes.fs({ ["a.log"] = "one\n" })
    local source = tail.file("a.log", { open = fs.open })
    t.eq((poll(source)), { "one" })
    t.eq((poll(source)), {})
    fs.files["a.log"] = "one\ntwo\nthree\n"
    t.eq((poll(source)), { "two", "three" })
  end)

  t.it("holds an unfinished line back until its newline arrives", function()
    local fs = fakes.fs({ ["a.log"] = "complete\npart" })
    local source = tail.file("a.log", { open = fs.open })
    t.eq((poll(source)), { "complete" })
    fs.files["a.log"] = "complete\npartial line\nnext"
    t.eq((poll(source)), { "partial line" })
    fs.files["a.log"] = "complete\npartial line\nnext\n"
    t.eq((poll(source)), { "next" })
  end)

  t.it("can start at the end of the file", function()
    local fs = fakes.fs({ ["a.log"] = "old 1\nold 2\n" })
    local source = tail.file("a.log", { open = fs.open, new_only = true })
    t.eq((poll(source)), {})
    fs.files["a.log"] = "old 1\nold 2\nnew\n"
    t.eq((poll(source)), { "new" })
  end)

  t.it("notices a file that shrank and reads the new content from the start", function()
    local fs = fakes.fs({ ["a.log"] = "aaaa 1\naaaa 2\naaaa 3\n" })
    local source = tail.file("a.log", { open = fs.open })
    t.eq((poll(source)), { "aaaa 1", "aaaa 2", "aaaa 3" })
    fs.files["a.log"] = "b 1\n"
    local got, status = poll(source)
    t.eq(got, { "b 1" })
    t.eq(status, "rotated")
    t.eq(select(2, poll(source)), "tailing", "the next poll is back to normal")
  end)

  t.it("notices a replaced file even when it is already longer than the old one", function()
    local fs = fakes.fs({ ["a.log"] = "first generation line one\n" })
    local source = tail.file("a.log", { open = fs.open })
    poll(source)
    fs.files["a.log"] = "second generation, a different first line\nand a second line\n"
    local got, status = poll(source)
    t.eq(status, "rotated")
    t.eq(got, { "second generation, a different first line", "and a second line" })
  end)

  t.it("treats a file that disappeared and came back as rotated", function()
    local fs = fakes.fs({ ["a.log"] = "x\n" })
    local source = tail.file("a.log", { open = fs.open })
    poll(source)
    fs.files["a.log"] = nil
    t.eq(select(2, poll(source)), "waiting")
    fs.files["a.log"] = "x\ny\n"
    local got, status = poll(source)
    t.eq(status, "rotated")
    t.eq(got, { "x", "y" })
  end)

  t.it("does not mistake a growing file for a replaced one", function()
    local fs = fakes.fs({ ["a.log"] = "GET /a\n" })
    local source = tail.file("a.log", { open = fs.open })
    poll(source)
    local content = "GET /a\n"
    for i = 1, 20 do
      content = content .. "GET /page" .. i .. "\n"
      fs.files["a.log"] = content
      local got, status = poll(source)
      t.eq(status, "tailing")
      t.eq(got, { "GET /page" .. i })
    end
  end)

  t.it("stops after a chunk when asked and resumes where it left off", function()
    local original = lines.CHUNK
    lines.CHUNK = 8
    local fs = fakes.fs({ ["a.log"] = "aaa\nbbb\nccc\nddd\neee\nfff\n" })
    local source = tail.file("a.log", { open = fs.open })
    local first = poll(source, function()
      return false
    end)
    t.ge(#first, 1, "a poll always makes progress")
    t.lt(#first, 6)
    local all = first
    for _ = 1, 20 do
      for _, line in ipairs((poll(source, function()
        return false
      end))) do
        all[#all + 1] = line
      end
    end
    t.eq(all, { "aaa", "bbb", "ccc", "ddd", "eee", "fff" })
    lines.CHUNK = original
  end)

  t.it("closes every handle it opens", function()
    local fs = fakes.fs({ ["a.log"] = "x\n" })
    local source = tail.file("a.log", { open = fs.open })
    for _ = 1, 5 do
      poll(source)
    end
    fs.files["a.log"] = "y\n"
    poll(source)
    t.eq(fs.opened, fs.closed)
    t.ge(fs.opened, 6)
  end)

  t.it("reports a file that cannot be positioned", function()
    local fs = fakes.fs({ ["pipe"] = "data\n" })
    fs.unseekable["pipe"] = true
    local _, status, err = poll(tail.file("pipe", { open = fs.open }))
    t.eq(status, "error")
    t.contains(err, "Illegal seek")
    t.eq(fs.opened, fs.closed)
  end)

  t.it("follows a real file written by another handle", function()
    local path = os.tmpname()
    local source = tail.file(path)
    local writer = assert(io.open(path, "wb"))
    writer:write("first\nsecond\n")
    writer:flush()
    t.eq((poll(source)), { "first", "second" })
    writer:write("third\npart")
    writer:flush()
    t.eq((poll(source)), { "third" })
    writer:write("ial\n")
    writer:flush()
    t.eq((poll(source)), { "partial" })
    writer:close()
    local truncated = assert(io.open(path, "wb"))
    truncated:write("new\n")
    truncated:close()
    local got, status = poll(source)
    os.remove(path)
    t.eq(status, "rotated")
    t.eq(got, { "new" })
  end)
end)

t.describe("tail.stream", function()
  t.it("reads line by line until the stream ends", function()
    local source = tail.stream(fakes.stdin("one\ntwo\nthree"))
    local got, status = poll(source)
    t.eq(got, { "one", "two", "three" })
    t.eq(status, "eof")
    t.eq(select(2, poll(source)), "eof")
  end)

  t.it("returns early when asked to stop", function()
    local source = tail.stream(fakes.stdin("a\nb\nc\n"))
    local seen = 0
    local got, status = poll(source, function()
      seen = seen + 1
      return seen < 2
    end)
    t.eq(got, { "a", "b" })
    t.eq(status, "tailing")
    t.eq((poll(source)), { "c" })
  end)

  t.it("reports a read error", function()
    local source = tail.stream({
      read = function()
        return nil, "broken pipe"
      end,
    })
    local _, status, err = poll(source)
    t.eq(status, "error")
    t.eq(err, "broken pipe")
  end)
end)
