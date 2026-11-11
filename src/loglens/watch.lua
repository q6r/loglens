--- Live mode: follows a growing log and redraws the terminal dashboard at a steady rate.
--
-- The loop owns no clock, terminal or file of its own. Everything outside the process arrives
-- through `hooks`, so the specs can drive it with fake time and fake files:
--
--     watch.run({ analyzer = analyzer, source = tail.file("access.log"), interval = 0.25 }, {
--       write = io.write, sleep = platform.sleep, clock = os.clock, size = platform.terminal_size,
--     })
--
-- Per frame it polls the source for new lines (within a time budget, so a big backlog fills the
-- dashboard progressively instead of freezing it), draws, and sleeps for what is left of the
-- interval. The terminal is always restored, also when the loop fails or Ctrl+C interrupts it.
-- @module loglens.watch
local terminal = require("loglens.render.terminal")

local M = {}

local ESC = "\27["
local HIDE_CURSOR, SHOW_CURSOR = ESC .. "?25l", ESC .. "?25h"
local ENTER_ALT, LEAVE_ALT = ESC .. "?1049h", ESC .. "?1049l"
local HOME, CLEAR_ALL, CLEAR_LINE, CLEAR_BELOW = ESC .. "H", ESC .. "2J", ESC .. "K", ESC .. "J"

--- Runs the loop.
-- @param opts table
--   `analyzer` (required) object with `feed(line)` and `summary()`;
--   `source` (required) a `loglens.tail` source;
--   `interval` seconds per frame (default 0.25);
--   `frames` stop after this many frames (default: run until the source ends or Ctrl+C);
--   `render` options for `terminal.render` (`color`, `ascii`, `width`; no `width` = use the terminal's);
--   `redraw` repaint in place with cursor control (default true); false appends frames instead;
--   `alt_screen` use the alternate screen (default: when repainting without a frame limit)
-- @param hooks table
--   `write(text)` and `sleep(seconds)` and `clock()` (seconds, any origin) are required;
--   `size()` optional, returns columns and rows of the terminal (asked every couple of seconds)
-- @return string reason the loop ended: `"frames"`, `"eof"`, `"interrupted"` or `"error"`
-- @return string|nil message for `"error"`
function M.run(opts, hooks)
  local analyzer, source = opts.analyzer, opts.source
  local render = opts.render or {}
  local interval = opts.interval or 0.25
  local redraw = opts.redraw ~= false
  local alt_screen = opts.alt_screen
  if alt_screen == nil then
    alt_screen = redraw and opts.frames == nil
  end
  local window = math.max(1, math.floor(1 / interval + 0.5))
  local size_every = math.max(1, math.ceil(2 / interval))
  local rotated_for = math.ceil(2 / interval)

  local recent, frame, hold = {}, 0, 0
  local cols, rows, painted_cols, painted_rows

  local function paint(live)
    local text = terminal.render(analyzer:summary(), {
      width = render.width or cols,
      color = render.color,
      ascii = render.ascii,
      frame = frame,
      live = live,
      max_lines = redraw and rows and rows - 1 or nil,
    })
    if not redraw then
      hooks.write((frame > 1 and "\n" or "") .. text)
      return
    end
    local resized = cols ~= painted_cols or rows ~= painted_rows
    painted_cols, painted_rows = cols, rows
    hooks.write((resized and CLEAR_ALL or "") .. HOME .. (text:gsub("\n", CLEAR_LINE .. "\n")) .. CLEAR_BELOW)
  end

  local function loop()
    while true do
      local started = hooks.clock()
      local deadline = started + interval
      local received = 0
      local status, err = source:poll(function(line)
        analyzer:feed(line)
        received = received + 1
      end, function()
        return hooks.clock() < deadline
      end)
      if status == "error" then
        return "error", err
      end
      frame = frame + 1
      if hooks.size and (frame == 1 or frame % size_every == 0) then
        cols, rows = hooks.size()
      end

      recent[#recent + 1] = received
      if #recent > window then
        table.remove(recent, 1)
      end
      local new_lines = 0
      for _, count in ipairs(recent) do
        new_lines = new_lines + count
      end
      if status == "rotated" then
        hold = rotated_for
      end
      local shown = status == "waiting" and "waiting" or (hold > 0 and "rotated" or "tailing")
      hold = math.max(0, hold - 1)

      if status == "eof" then
        -- The stream ended: leave the last frame behind as a plain report, without the LIVE header.
        if alt_screen then
          hooks.write(LEAVE_ALT)
          alt_screen, redraw = false, false
        end
        paint(nil)
        return "eof"
      end
      paint({ status = shown, new_lines = new_lines })
      if opts.frames and frame >= opts.frames then
        return "frames"
      end
      local spent = hooks.clock() - started
      if spent < interval then
        hooks.sleep(interval - spent)
      end
    end
  end

  -- Cursor control only when repainting in place: appended frames may be going into a file.
  local controlled = redraw
  if controlled then
    hooks.write(HIDE_CURSOR .. (alt_screen and ENTER_ALT or ""))
  end
  local ok, reason, err = pcall(loop)
  if controlled then
    hooks.write((alt_screen and LEAVE_ALT or "") .. SHOW_CURSOR)
  end
  if not ok then
    if tostring(reason):find("interrupted", 1, true) then
      return "interrupted"
    end
    error(reason, 0)
  end
  return reason, err
end

return M
