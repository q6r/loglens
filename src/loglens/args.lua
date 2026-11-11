--- A small command-line option parser: long options (`--top 5`, `--top=5`), one-letter aliases
-- (`-n 5`, `-n5`), flags, `--` to end the options and `-` as an ordinary argument (standard input).
--
-- The parser only splits and converts; what a value means is up to the caller. Unknown options are
-- rejected with a suggestion, so a typo never silently turns into a file name.
-- @module loglens.args
local util = require("loglens.util")

local M = {}

local match, sub = string.match, string.sub

--- Option declarations are plain tables:
--
--     { name = "top", short = "n", value = "N", kind = "integer", help = "rows per list" }
--
-- `value` (the placeholder shown in help) makes the option take an argument, `kind` converts it
-- (`"string"` by default, `"number"` or `"integer"`), and `choices` restricts the accepted strings.
-- Options without `value` are flags.
-- @table Option

local function convert(option, text)
  local kind = option.kind or "string"
  if kind == "string" then
    if option.choices then
      for _, choice in ipairs(option.choices) do
        if choice == text then
          return text
        end
      end
      return nil, string.format("invalid value '%s' for --%s (expected %s)", text, option.name,
        table.concat(option.choices, ", "))
    end
    return text
  end
  local number = tonumber(text)
  if not number or number ~= number or number == math.huge or number == -math.huge then
    return nil, string.format("invalid value '%s' for --%s (expected a number)", text, option.name)
  end
  if kind == "integer" then
    if math.type(number) ~= "integer" and number ~= math.floor(number) then
      return nil, string.format("invalid value '%s' for --%s (expected a whole number)", text,
        option.name)
    end
    number = math.tointeger(number) or number
  end
  return number
end

--- Parses `argv` against option declarations.
-- @param argv string[] arguments (without the program name or the command)
-- @param options table[] array of option declarations (see `Option`)
-- @return table|nil `{ options = { top = 5, no_color = true, ... }, args = { "access.log" } }`; option
--   names have their dashes replaced by underscores
-- @return string|nil message describing the first problem
function M.parse(argv, options)
  local by_name, by_short, names = {}, {}, {}
  for _, option in ipairs(options) do
    by_name[option.name] = option
    names[#names + 1] = "--" .. option.name
    if option.short then
      by_short[option.short] = option
    end
  end

  local parsed = { options = {}, args = {} }

  local function unknown(word)
    local hint = util.suggest(word, names)
    return nil, string.format("unknown option '%s'%s", word,
      hint and (". Did you mean '" .. hint .. "'?") or "")
  end

  local function store(option, text)
    local value, err
    if option.value then
      value, err = convert(option, text)
      if err then
        return err
      end
    else
      value = true
    end
    parsed.options[(option.name:gsub("-", "_"))] = value
  end

  local i, count = 1, #argv
  while i <= count do
    local word = argv[i]
    i = i + 1
    if word == "--" then
      for j = i, count do
        parsed.args[#parsed.args + 1] = argv[j]
      end
      break
    elseif sub(word, 1, 2) == "--" then
      local name, inline = match(word, "^%-%-([^=]+)=(.*)$")
      name = name or sub(word, 3)
      local option = by_name[name]
      if not option then
        return unknown(word)
      end
      local text = inline
      if option.value then
        if text == nil then
          text, i = argv[i], i + 1
          if text == nil then
            return nil, string.format("option '--%s' needs a value (%s)", name, option.value)
          end
        end
      elseif text ~= nil then
        return nil, string.format("option '--%s' does not take a value", name)
      end
      local err = store(option, text)
      if err then
        return nil, err
      end
    elseif sub(word, 1, 1) == "-" and #word > 1 then
      local letter, attached = sub(word, 2, 2), sub(word, 3)
      local option = by_short[letter]
      if not option then
        return unknown(word)
      end
      local text
      if option.value then
        if attached ~= "" then
          text = attached
        else
          text, i = argv[i], i + 1
          if text == nil then
            return nil, string.format("option '-%s' needs a value (%s)", letter, option.value)
          end
        end
      elseif attached ~= "" then
        return nil, string.format("option '-%s' does not take a value (combine flags separately)",
          letter)
      end
      local err = store(option, text)
      if err then
        return nil, err
      end
    else
      parsed.args[#parsed.args + 1] = word
    end
  end
  return parsed
end

--- Formats option declarations as an aligned help table.
-- @param options table[] declarations
-- @return string[] lines, each starting with two spaces
function M.help_lines(options)
  local left, width = {}, 0
  for i, option in ipairs(options) do
    local text = option.short and ("-" .. option.short .. ", ") or "    "
    text = text .. "--" .. option.name
    if option.value then
      text = text .. " " .. option.value
    end
    left[i] = text
    width = math.max(width, #text)
  end
  local lines = {}
  for i, option in ipairs(options) do
    lines[i] = "  " .. left[i] .. string.rep(" ", width - #left[i] + 2) .. option.help
  end
  return lines
end

return M
