local t = require("spec.support")
local analyzer = require("loglens.analyzer")
local loggen = require("tools.loggen")
local watch = require("loglens.watch")

local HIDE_CURSOR, SHOW_CURSOR = "\27[?25l", "\27[?25h"
local ENTER_ALT, LEAVE_ALT = "\27[?1049h", "\27[?1049l"
local HOME, CLEAR_ALL, CLEAR_BELOW = "\27[H", "\27[2J", "\27[J"

local LOG = loggen.lines({ seed = 3, count = 60, attacks = false })

-- Hooks with a clock that only moves when the loop sleeps (or a source spends time).
local function hooks(opts)
  opts = opts or {}
  local h = { writes = {}, sleeps = {}, now = 0, size_calls = 0 }
  h.write = function(text)
    h.writes[#h.writes + 1] = text
  end
  h.sleep = function(seconds)
    h.sleeps[#h.sleeps + 1] = seconds
    h.now = h.now + seconds
  end
  h.clock = function()
    return h.now
  end
  if opts.sizes then
    h.size = function()
      h.size_calls = h.size_calls + 1
      local size = opts.sizes[math.min(h.size_calls, #opts.sizes)]
      return size[1], size[2]
    end
  end
  return h
end

-- A source that plays back a script: each poll consumes one step.
local function scripted(steps)
  local index = 0
  local source = {}
  function source:poll(emit)
    index = index + 1
    local step = steps[math.min(index, #steps)]
    if step.fail then
      error(step.fail, 0)
    end
    for _, line in ipairs(step.lines or {}) do
      emit(line)
    end
    return step.status or "tailing", step.message
  end
  return source
end

local function new_analyzer()
  return analyzer.new({ format = "combined", sources = { "live.log" }, now = 1794400000 })
end

-- The frames a run wrote: everything between the cursor/screen controls.
local function frames_of(h)
  local out = {}
  for i = 2, #h.writes - 1 do
    out[#out + 1] = h.writes[i]
  end
  return out
end

local function header(frame)
  return frame:gsub("^\27%[2J", ""):gsub("^\27%[H", ""):match("^([^\n\27]*)")
end

t.describe("watch.run", function()
  t.it("repaints in place, sleeps for the rest of the interval and restores the terminal", function()
    local h = hooks()
    local reason = watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG } }), interval = 0.25,
      frames = 3, render = { color = false, width = 100 } }, h)
    t.eq(reason, "frames")
    t.eq(h.writes[1], HIDE_CURSOR, "a frame limit means no alternate screen: the last frame stays visible")
    t.eq(h.writes[#h.writes], SHOW_CURSOR)
    local frames = frames_of(h)
    t.eq(#frames, 3)
    for _, frame in ipairs(frames) do
      t.eq(frame:sub(1, #HOME), HOME)
      t.eq(frame:sub(-#CLEAR_BELOW), CLEAR_BELOW)
      t.contains(frame, "LIVE")
      t.contains(frame, "REQUESTS")
      t.contains(frame, "\27[K\n", "every line clears its own tail")
    end
    t.eq(h.sleeps, { 0.25, 0.25 }, "no sleep after the last frame")
  end)

  t.it("uses the alternate screen without a frame limit and leaves a plain report when the stream ends", function()
    local h = hooks()
    local reason = watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG }, {}, { status = "eof" } }),
      interval = 0.25, render = { color = false, width = 100 } }, h)
    t.eq(reason, "eof")
    t.eq(h.writes[1], HIDE_CURSOR .. ENTER_ALT)
    t.eq(h.writes[#h.writes], SHOW_CURSOR)
    t.eq(h.writes[#h.writes - 2], LEAVE_ALT)
    local final = h.writes[#h.writes - 1]
    t.not_contains(final, "LIVE", "the last frame is a normal report")
    t.not_contains(final, "\27")
    t.contains(final, "REQUESTS")
    t.eq(#h.sleeps, 2)
  end)

  t.it("appends frames without any control sequence when not repainting", function()
    local h = hooks()
    watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG } }), interval = 0.25, frames = 2,
      redraw = false, render = { color = false, width = 100 } }, h)
    t.eq(#h.writes, 2)
    for _, text in ipairs(h.writes) do
      t.not_contains(text, "\27")
    end
    t.eq(h.writes[2]:sub(1, 1), "\n", "frames are separated by a blank line")
    t.eq(h.writes[1]:sub(1, 1), " ")
  end)

  t.it("counts the lines of the last second in the header", function()
    local h = hooks()
    local five = { LOG[1], LOG[2], LOG[3], LOG[4], LOG[5] }
    watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = { LOG[6], LOG[7], LOG[8] } },
      { lines = five }, {}, {}, {}, {} }), interval = 0.25, frames = 6, render = { color = false, width = 100 } }, h)
    local counts = {}
    for i, frame in ipairs(frames_of(h)) do
      counts[i] = header(frame):match("%+(%d+) new")
    end
    t.eq(counts, { "3", "8", "8", "8", "5", "0" }, "a window of four frames at 0.25 s")
  end)

  t.it("shows a rotation for about two seconds, then goes back to normal", function()
    local h = hooks()
    watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG }, { status = "rotated" }, {}, {}, {}, {},
      {}, {} }), interval = 0.5, frames = 8, render = { color = false, width = 120 } }, h)
    local shown = {}
    for i, frame in ipairs(frames_of(h)) do
      shown[i] = header(frame):find("log rotated, following the new file", 1, true) and "rotated" or "normal"
    end
    t.eq(shown, { "normal", "rotated", "rotated", "rotated", "rotated", "normal", "normal", "normal" })
  end)

  t.it("says so while the file does not exist", function()
    local h = hooks()
    watch.run({ analyzer = new_analyzer(), source = scripted({ { status = "waiting" } }), interval = 0.25, frames = 1,
      render = { color = false, width = 100 } }, h)
    local frame = frames_of(h)[1]
    t.contains(frame, "waiting for the file")
    t.contains(frame, "Waiting for the first request.")
  end)

  t.it("reads a backlog in slices so the dashboard keeps filling", function()
    local h = hooks()
    local backlog, index = {}, 0
    for i = 1, 60 do
      backlog[i] = LOG[i]
    end
    local source = {}
    function source:poll(emit, keep_going)
      repeat
        index = index + 1
        emit(backlog[index])
        h.now = h.now + 0.1 -- every line costs 0.1 s
      until index >= #backlog or not keep_going()
      return "tailing"
    end
    watch.run({ analyzer = new_analyzer(), source = source, interval = 0.25, frames = 4,
      render = { color = false, width = 100 } }, h)
    t.eq(index, 12, "three lines per 0.25 s budget, four frames")
    t.eq(h.sleeps, {}, "a frame that used its whole budget does not sleep")
    local parsed = {}
    for i, frame in ipairs(frames_of(h)) do
      parsed[i] = tonumber(frame:match("parsed (%d+) of"))
    end
    t.eq(parsed, { 3, 6, 9, 12 })
  end)

  t.it("asks for the terminal size every couple of seconds, clears on resize and fits the height", function()
    local h = hooks({ sizes = { { 100, 40 }, { 80, 24 } } })
    watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG } }), interval = 0.5, frames = 9,
      render = { color = false } }, h)
    t.eq(h.size_calls, 3, "frames 1, 4 and 8")
    local frames = frames_of(h)
    t.eq(frames[1]:sub(1, #CLEAR_ALL), CLEAR_ALL, "the first frame clears the screen")
    t.eq(frames[2]:sub(1, #HOME), HOME)
    t.eq(frames[4]:sub(1, #CLEAR_ALL), CLEAR_ALL, "the size changed")
    t.eq(frames[5]:sub(1, #HOME), HOME, "and then stayed the same")
    local function height(frame)
      return select(2, frame:gsub("\n", "\n"))
    end
    t.lt(height(frames[1]), 40, "a 40 row terminal keeps a free row")
    t.lt(height(frames[4]), 24, "and so does a 24 row one")
    t.ge(height(frames[1]), height(frames[4]), "the taller terminal shows at least as much")
    for _, section in ipairs({ "REQUESTS", "TRAFFIC", "STATUS" }) do
      t.contains(frames[4], section, "the essentials survive on a short terminal")
    end
    t.not_contains(frames[4], "TOP PATHS", "the lists are what makes room")
    t.contains(frames[1], "TOP PATHS")
  end)

  t.it("returns a source error and still restores the terminal", function()
    local h = hooks()
    local reason, message = watch.run({ analyzer = new_analyzer(), source = scripted({ { status = "error", message = "boom" } }),
      interval = 0.25 }, h)
    t.eq(reason, "error")
    t.eq(message, "boom")
    t.eq(h.writes[#h.writes], LEAVE_ALT .. SHOW_CURSOR)
  end)

  t.it("treats an interrupt as a clean stop", function()
    local h = hooks()
    local reason = watch.run({ analyzer = new_analyzer(), source = scripted({ { lines = LOG },
      { fail = "src/loglens/watch.lua:57: interrupted!" } }), interval = 0.25, render = { color = false } }, h)
    t.eq(reason, "interrupted")
    t.eq(h.writes[#h.writes], LEAVE_ALT .. SHOW_CURSOR)
  end)

  t.it("restores the terminal before rethrowing any other failure", function()
    local h = hooks()
    t.raises(function()
      watch.run({ analyzer = new_analyzer(), source = scripted({ { fail = "kaboom" } }), interval = 0.25 }, h)
    end, "kaboom")
    t.eq(h.writes[#h.writes], LEAVE_ALT .. SHOW_CURSOR)
  end)
end)
