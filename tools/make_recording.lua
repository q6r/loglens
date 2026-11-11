--- Builds docs/screenshots/watch.svg: an animated "recording" of the live dashboard made of real
-- frames of `loglens watch` (the actual renderer driven by the actual watch loop) over
-- examples/access.log, in a near-black terminal window with a soft glow behind it. The SVG is plain
-- markup with a CSS animation (no script, no external reference), so it plays inside GitHub's <img>
-- sandbox; with `prefers-reduced-motion` it shows the last frame only.
--
--     lua tools/make_recording.lua        (run from the project root; writes docs/screenshots/watch.svg)
-- @script tools.make_recording
package.path = "src/?.lua;src/?/init.lua;?.lua;" .. package.path

local analyzer = require("loglens.analyzer")
local watch = require("loglens.watch")

local COLUMNS, ROWS = 120, 44
local LINES_PER_FRAME = 12
-- Frames of the run that are shown. Frame 286 is the one where the last line of the sample arrives (and the
-- frame of the README's hero image); it lingers at the end of the loop.
local KEEP = { 12, 36, 60, 84, 108, 132, 156, 180, 204, 232, 260, 286, 286 }
local SECONDS_PER_FRAME = 0.9
local COMMAND = "loglens watch examples/access.log"

-- Geometry, in SVG units: the character grid, the window and the ground around it.
local CELL_W, CELL_H, ASCENT = 7.8, 19, 14
local MARGIN, BAR_HEIGHT, PAD_X, PAD_TOP, PAD_BOTTOM = 36, 35, 22, 18, 22

-- The terminal palette (near-black ground, silver ink, indigo accent). The dashboard speaks in
-- xterm-256 colours; they are shown as the matching colours of this palette.
local GROUND, WINDOW, BAR, INK, TITLE_INK = "#0c0c10", "#121216", "#16161b", "#d8dade", "#858791"
local HAIRLINE = 0.09
local COLOURS = {
  black = "#1a1a22",
  red = "#e66767",
  green = "#3dbd91",
  yellow = "#d9a521",
  blue = "#7f86f0",
  cyan = "#4aaee0",
  orange = "#ec835a",
  grey = "#6a6c75",
}
local MUTED = 245 -- the dashboard's secondary text: the ink at reduced opacity
local DIM_OPACITY = ".62"
local FOREGROUND = {
  [16] = COLOURS.black,
  [75] = COLOURS.cyan,
  [78] = COLOURS.green,
  [81] = COLOURS.blue,
  [203] = COLOURS.red,
  [221] = COLOURS.yellow,
}
local BACKGROUND = {
  [110] = COLOURS.blue,
  [203] = COLOURS.red,
  [208] = COLOURS.orange,
  [221] = COLOURS.yellow,
  [245] = COLOURS.grey,
}

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

local function escape(text)
  return (text:gsub("[&<>]", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;" }))
end

-- Black text on a coloured badge becomes whichever of near-black and white contrasts more with it.
local function readable_on(colour)
  local function linear(hex)
    local value = tonumber(hex, 16) / 255
    return value <= 0.03928 and value / 12.92 or ((value + 0.055) / 1.055) ^ 2.4
  end
  local luminance = 0.2126 * linear(colour:sub(2, 3)) + 0.7152 * linear(colour:sub(4, 5))
    + 0.0722 * linear(colour:sub(6, 7))
  return 1.05 / (luminance + 0.05) > (luminance + 0.05) / 0.05 and "#ffffff" or "#0b0b0e"
end

local TEXT_X = MARGIN + 1 + PAD_X

-- One line of ANSI text -> SVG: background boxes and tspans placed on the character grid.
-- `baseline` is the y of the text baseline.
local function line_to_svg(line, baseline)
  local boxes, spans, style, column = {}, {}, { bold = false, dim = false }, 0
  local function emit(text)
    if text == "" then
      return
    end
    local width = utf8.len(text) or #text
    local x = TEXT_X + column * CELL_W
    if style.bg then
      boxes[#boxes + 1] = string.format('<rect x="%.1f" y="%.1f" width="%.1f" height="%d" fill="%s"/>', x,
        baseline - ASCENT, width * CELL_W, CELL_H - 1, style.bg)
    end
    if text:find("%S") then
      local fill = style.fg or INK
      if style.bg and fill == COLOURS.black then
        fill = readable_on(style.bg)
      end
      -- textLength pins each run to its cells, so the grid holds in any monospace (or fallback) font
      spans[#spans + 1] = string.format('<tspan x="%.1f" textLength="%.1f" fill="%s"%s%s>%s</tspan>', x,
        width * CELL_W, fill, style.bold and ' font-weight="700"' or "",
        style.dim and (' fill-opacity="' .. DIM_OPACITY .. '"') or "", escape(text))
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
          local code = numbers[i + 2]
          if n == 48 then
            style.bg = BACKGROUND[code] or COLOURS.grey
          elseif code == MUTED then
            style.dim = true
          else
            style.fg = FOREGROUND[code] or INK
          end
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
  local text = #spans > 0 and ('<text y="' .. baseline .. '">' .. table.concat(spans) .. "</text>") or ""
  return table.concat(boxes) .. text
end

local frames = capture_frames()
local top = MARGIN + 1 + BAR_HEIGHT + PAD_TOP
local out = {}
local rows = 0
for slot, number in ipairs(KEEP) do
  local group = {}
  local row, drawn = 0, 0
  for line in frames[number]:gmatch("[^\n]+") do
    row = row + 1
    local svg_line = line_to_svg(line, top + (row + 1) * CELL_H - 4) -- row 1 is the prompt
    group[#group + 1] = svg_line
    if svg_line ~= "" then
      drawn = row -- blank lines at the end of a frame do not make the window taller
    end
  end
  rows = math.max(rows, drawn)
  local last = slot == #KEEP
  out[#out + 1] = string.format('<g class="%s" style="animation-delay:%.2fs">%s</g>', last and "f l" or "f",
    (slot - 1) * SECONDS_PER_FRAME, table.concat(group))
end

local window_w = math.floor(COLUMNS * CELL_W + 0.5) + 2 * PAD_X + 2
local window_h = 1 + BAR_HEIGHT + PAD_TOP + (rows + 1) * CELL_H + PAD_BOTTOM + 1
local width, height = window_w + 2 * MARGIN, window_h + 2 * MARGIN
local total = #KEEP * SECONDS_PER_FRAME

local prompt = string.format(
  '<text y="%d"><tspan x="%.1f" textLength="%.1f" fill="%s" font-weight="700">$</tspan>'
    .. '<tspan x="%.1f" textLength="%.1f" fill="%s" font-weight="600">%s</tspan></text>',
  top + CELL_H - 4, TEXT_X, CELL_W, COLOURS.blue, TEXT_X + 2 * CELL_W, #COMMAND * CELL_W, INK, escape(COMMAND))

local svg = string.format(
  [[
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="Recording of loglens watch examples/access.log: the dashboard fills as requests arrive and findings appear">
<title>%s</title>
<defs>
<radialGradient id="ga"><stop offset="0" stop-color="%s" stop-opacity=".2"/><stop offset="1" stop-color="%s" stop-opacity="0"/></radialGradient>
<radialGradient id="gb"><stop offset="0" stop-color="#6f76e6" stop-opacity=".46"/><stop offset="1" stop-color="#6f76e6" stop-opacity="0"/></radialGradient>
<clipPath id="win"><rect x="%d" y="%d" width="%d" height="%d" rx="16"/></clipPath>
</defs>
<style>
text{font:13px/1 ui-monospace,"Cascadia Code","SF Mono",SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono","Liberation Mono",monospace;white-space:pre}
.t{font:500 12px/1 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.f{opacity:0;animation:show %.1fs steps(1,end) infinite}
@keyframes show{0%%{opacity:1}%.3f%%{opacity:0}100%%{opacity:0}}
@media (prefers-reduced-motion:reduce){.f{animation:none}.f.l{opacity:1}}
</style>
<rect width="%d" height="%d" fill="%s"/>
<ellipse cx="%.1f" cy="-34" rx="%.1f" ry="197" fill="url(#ga)"/>
<ellipse cx="%.1f" cy="-29" rx="%.1f" ry="178" fill="url(#gb)"/>
<g clip-path="url(#win)"><rect x="%d" y="%d" width="%d" height="%d" fill="%s"/><rect x="%d" y="%d" width="%d" height="%d" fill="%s"/><rect x="%d" y="%d" width="%d" height="1" fill="%s" fill-opacity="%s"/></g>
<rect x="%.1f" y="%.1f" width="%d" height="%d" rx="15.5" fill="none" stroke="%s" stroke-opacity="%s"/>
<circle cx="%d" cy="%d" r="6" fill="%s"/><circle cx="%d" cy="%d" r="6" fill="%s"/><circle cx="%d" cy="%d" r="6" fill="%s"/>
<text class="t" x="%.1f" y="%d" fill="%s" text-anchor="middle">%s</text>
%s
%s
</svg>
]],
  width, height, width, height, escape(COMMAND), INK, INK,
  MARGIN, MARGIN, window_w, window_h,
  total, 100 / #KEEP,
  width, height, GROUND, width * 0.56, width * 0.54, width * 0.95, width * 0.4,
  MARGIN, MARGIN, window_w, window_h, WINDOW,
  MARGIN, MARGIN, window_w, BAR_HEIGHT, BAR,
  MARGIN, MARGIN + BAR_HEIGHT, window_w, INK, tostring(HAIRLINE),
  MARGIN + 0.5, MARGIN + 0.5, window_w - 1, window_h - 1, INK, tostring(HAIRLINE),
  MARGIN + 21, MARGIN + 18, "#e66767", MARGIN + 41, MARGIN + 18, "#c98500", MARGIN + 61, MARGIN + 18, "#1aa384",
  MARGIN + window_w / 2 - 22, MARGIN + 22, TITLE_INK, escape(COMMAND),
  prompt, table.concat(out, "\n"))

local file = assert(io.open("docs/screenshots/watch.svg", "wb"))
assert(file:write(svg))
file:close()
print(string.format("wrote docs/screenshots/watch.svg (%d bytes, %d frames, %.1f s loop)", #svg, #KEEP, total))
