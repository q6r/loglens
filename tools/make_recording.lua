--- Builds docs/screenshots/watch.svg: an animated "recording" of the live dashboard made of real
-- frames of `loglens watch` (the actual renderer driven by the actual watch loop) over
-- examples/access.log. The SVG is plain markup with a CSS animation, so it plays inside GitHub's
-- <img> sandbox.
--
--     lua tools/make_recording.lua        (run from the project root; writes docs/screenshots/watch.svg)
-- @script tools.make_recording
package.path = "src/?.lua;src/?/init.lua;?.lua;" .. package.path

local analyzer = require("loglens.analyzer")
local watch = require("loglens.watch")

local COLUMNS, ROWS = 110, 36
local LINES_PER_FRAME = 12
local KEEP = { 12, 36, 60, 84, 108, 132, 156, 180, 204, 232, 260, 290, 290 } -- the last frame lingers
local CELL_W, CELL_H, PAD = 7.8, 17, 18
local SECONDS_PER_FRAME = 0.9

-- Frames of the real watch loop, in colour, with a fixed clock so the output is reproducible.
local function capture_frames()
  local lines = {}
  for line in io.lines("examples/access.log") do
    lines[#lines + 1] = line
  end
  local index, now, frames = 0, 0, {}
  local source = {
    poll = function(_, emit)
      for _ = 1, LINES_PER_FRAME do
        index = index + 1
        if lines[index] then
          emit(lines[index])
        end
      end
      return "tailing"
    end,
  }
  watch.run({
    analyzer = analyzer.new({ sources = { "examples/access.log" }, now = 1794830400 }),
    source = source,
    interval = 0.25,
    frames = KEEP[#KEEP],
    render = { color = true },
  }, {
    write = function(text)
      if text:find("LIVE", 1, true) then
        frames[#frames + 1] = text
      end
    end,
    sleep = function(seconds)
      now = now + seconds
    end,
    clock = function()
      return now
    end,
    size = function()
      return COLUMNS, ROWS
    end,
  })
  return frames
end

local LEVELS = { 0, 95, 135, 175, 215, 255 }
local function xterm_color(n) -- 256-colour palette index -> "#rrggbb"
  if n >= 232 then
    return string.format("#%02x%02x%02x", 8 + (n - 232) * 10, 8 + (n - 232) * 10, 8 + (n - 232) * 10)
  elseif n >= 16 then
    n = n - 16
    return string.format("#%02x%02x%02x", LEVELS[n // 36 + 1], LEVELS[n % 36 // 6 + 1], LEVELS[n % 6 + 1])
  end
  return "#c9d1d9"
end

local function escape(text)
  return (text:gsub("[&<>]", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;" }))
end

-- One line of ANSI text -> SVG: background boxes and tspans placed on the character grid.
local function line_to_svg(line, y)
  local boxes, spans, style, column = {}, {}, { fg = nil, bg = nil, bold = false, dim = false }, 0
  local function emit(text)
    if text == "" then
      return
    end
    local width = utf8.len(text) or #text
    local x = PAD + column * CELL_W
    if style.bg then
      boxes[#boxes + 1] = string.format('<rect x="%.1f" y="%.1f" width="%.1f" height="%d" fill="%s"/>', x,
        y - 13, width * CELL_W, CELL_H - 1, style.bg)
    end
    if text:find("%S") then
      -- textLength pins each run to its cells, so the grid holds in any monospace (or fallback) font
      spans[#spans + 1] = string.format('<tspan x="%.1f" textLength="%.1f" fill="%s"%s%s>%s</tspan>', x,
        width * CELL_W, style.fg or "#c9d1d9", style.bold and ' font-weight="700"' or "",
        style.dim and ' fill-opacity=".6"' or "", escape(text))
    end
    column = column + width
  end
  local position = 1
  while position <= #line do
    local start, stop, codes = line:find("\27%[([%d;]*)m", position)
    local control = line:find("\27%[[%d;?]*[HJK]", position)
    if control and (not start or control < start) then
      local _, finish = line:find("\27%[[%d;?]*[HJK]", control)
      emit(line:sub(position, control - 1))
      position = finish + 1
    elseif start then
      emit(line:sub(position, start - 1))
      local numbers = {}
      for number in (codes == "" and "0" or codes):gmatch("%d+") do
        numbers[#numbers + 1] = tonumber(number)
      end
      local i = 1
      while i <= #numbers do
        local n = numbers[i]
        if n == 0 then
          style = { bold = false, dim = false }
        elseif n == 1 or n == 2 then
          style[n == 1 and "bold" or "dim"] = true
        elseif (n == 38 or n == 48) and numbers[i + 1] == 5 then
          style[n == 38 and "fg" or "bg"] = xterm_color(numbers[i + 2])
          i = i + 2
        end
        i = i + 1
      end
      position = stop + 1
    else
      emit(line:sub(position))
      break
    end
  end
  return table.concat(boxes) .. (#spans > 0 and ('<text y="' .. y .. '">' .. table.concat(spans) .. "</text>") or "")
end

local frames = capture_frames()
local width = math.floor(COLUMNS * CELL_W + PAD * 2)
local total = #KEEP * SECONDS_PER_FRAME
local out = {}
local height
for slot, number in ipairs(KEEP) do
  local group = {}
  local row = 0
  for line in frames[number]:gmatch("[^\n]+") do
    row = row + 1
    group[#group + 1] = line_to_svg(line, PAD + 36 + row * CELL_H)
  end
  height = math.max(height or 0, PAD * 2 + 36 + row * CELL_H)
  out[#out + 1] = string.format('<g class="f" style="animation-delay:%.2fs">%s</g>', (slot - 1) * SECONDS_PER_FRAME,
    table.concat(group))
end

local svg = string.format([[
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="Recording of loglens watch examples/access.log: the dashboard fills as requests arrive and findings appear">
<title>loglens watch examples/access.log</title>
<style>
text{font:13px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;white-space:pre}
.f{opacity:0;animation:show %.1fs steps(1,end) infinite}
@keyframes show{0%%{opacity:1}%.3f%%{opacity:0}100%%{opacity:0}}
</style>
<rect width="%d" height="%d" rx="12" fill="#0b1020"/>
<rect width="%d" height="30" rx="12" fill="#151b2e"/>
<circle cx="20" cy="15" r="5" fill="#ff5f57"/><circle cx="38" cy="15" r="5" fill="#febc2e"/><circle cx="56" cy="15" r="5" fill="#28c840"/>
<text x="%d" y="19" fill="#8b93a7" text-anchor="middle" style="font-size:11px">loglens watch examples/access.log</text>
%s
</svg>
]], width, height, width, height, total, 100 / #KEEP, width, height, width, width // 2, table.concat(out, "\n"))

local file = assert(io.open("docs/screenshots/watch.svg", "wb"))
assert(file:write(svg))
file:close()
print(string.format("wrote docs/screenshots/watch.svg (%d bytes, %d frames, %.1f s loop)", #svg, #KEEP, total))
