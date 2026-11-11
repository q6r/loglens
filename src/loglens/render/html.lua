--- Single-file HTML report: the bundled Aurora UI kit, the report view and the data in one document.
--
-- The page needs no network and no server. The document itself is almost empty: a `<noscript>`
-- fallback, the data and the scripts; `report.js` builds the whole layout (navigation rail,
-- breadcrumbs, view switch, content, status bar) from the data. The summary travels as a JSON island
-- that cannot be closed by hostile log text (`island` escapes `<`, `>`, `&`, U+2028 and U+2029), the
-- view code draws every string with `textContent`, and a Content-Security-Policy meta tag pins the
-- inline styles and scripts by SHA-256, so even injected markup could neither run nor reach the
-- network. Without JavaScript the page falls back to the plain-text terminal dashboard.
-- @module loglens.render.html
local sha256 = require("loglens.sha256")
local summary_module = require("loglens.summary")
local terminal = require("loglens.render.terminal")
local util = require("loglens.util")
local version = require("loglens.version")

local M = {}

local ASSET_FILES = { "aurora.css", "aurora.js", "aurora-charts.js", "report.css", "report.js" }

local HTML_ESCAPES = {
  ["&"] = "&amp;",
  ["<"] = "&lt;",
  [">"] = "&gt;",
  ['"'] = "&quot;",
  ["'"] = "&#39;",
}

--- Escapes text for HTML element content and attribute values.
-- @param text string
-- @return string
function M.escape(text)
  return (text:gsub("[&<>\"']", HTML_ESCAPES))
end

--- Makes serialised JSON safe to embed in a `<script>` element: `<`, `>` and `&` become `\u003c`,
-- `\u003e` and `\u0026`, U+2028 and U+2029 become `\u2028` and `\u2029`. All of these are legal
-- inside JSON strings, so `JSON.parse` restores the original text, but the result can no longer
-- contain `</script>` or `<!--`.
-- @param json_text string JSON produced by our own encoder
-- @return string
function M.island(json_text)
  json_text = json_text:gsub("[<>&]", function(char)
    return string.format("\\u%04x", char:byte())
  end)
  json_text = json_text:gsub("\226\128\168", "\\u2028")
  json_text = json_text:gsub("\226\128\169", "\\u2029")
  return json_text
end

-- Directory of the bundled UI kit and report view files, next to this module (src/loglens/assets).
local function default_assets_dir()
  local info = debug and debug.getinfo(1, "S")
  local source = info and info.source or ""
  local directory = source:sub(1, 1) == "@" and source:sub(2):match("^(.*)[/\\][^/\\]*$")
  if not directory then
    return nil, "cannot locate the report assets; pass opts.assets_dir"
  end
  return directory .. "/../assets"
end

-- Source checkouts keep the assets in one folder; the rockspec installs each file into a folder
-- of its own (`aurora_css/aurora.css`), because LuaRocks maps one module directory per entry.
local function open_asset(directory, name)
  local file, err = io.open(directory .. "/" .. name, "rb")
  if file then
    return file
  end
  local nested = io.open(directory .. "/" .. name:gsub("%.", "_") .. "/" .. name, "rb")
  return nested, err
end

local function read_assets(directory)
  local assets = {}
  for _, name in ipairs(ASSET_FILES) do
    local file, err = open_asset(directory, name)
    if not file then
      return nil, "cannot read the report asset " .. tostring(err)
    end
    local text = file:read("a")
    file:close()
    local lower = text:lower()
    if lower:find("</script", 1, true) or lower:find("<!--", 1, true) then
      return nil, "report asset " .. name .. " contains markup that is unsafe inside <script>"
    end
    assets[name] = text
  end
  return assets
end

local function page_title(summary)
  local sources = summary.meta.sources
  local name = #sources == 1 and util.defang(sources[1], 80) or (#sources > 1 and #sources .. " files")
  return "loglens report" .. (name and (" - " .. name) or "")
end

--- Renders the report.
-- @param summary table a `loglens.summary/v1` table
-- @param opts table|nil `{ assets_dir = "<path>" }` to read the UI kit and report view files from elsewhere
-- @return string|nil the complete HTML document
-- @return string|nil message when the summary is invalid or an asset is missing
function M.render(summary, opts)
  opts = opts or {}
  local valid, problems = summary_module.validate(summary)
  if not valid then
    return nil, "invalid summary: " .. problems[1]
  end
  local directory = opts.assets_dir
  if not directory then
    local err
    directory, err = default_assets_dir()
    if not directory then
      return nil, err
    end
  end
  local assets, err = read_assets(directory)
  if not assets then
    return nil, err
  end

  local style = assets["aurora.css"] .. "\n" .. assets["report.css"]
  local scripts = { assets["aurora.js"], assets["aurora-charts.js"], assets["report.js"] }
  local script_sources = {}
  for i, script in ipairs(scripts) do
    script_sources[i] = sha256.csp_source(script)
  end
  local policy = table.concat({
    "default-src 'none'",
    "script-src " .. table.concat(script_sources, " "),
    "style-src " .. sha256.csp_source(style),
    "img-src data:",
    "base-uri 'none'",
    "form-action 'none'",
  }, "; ")

  local data = M.island(summary_module.encode(summary, { indent = 0, html_safe = true }))
  local fallback = terminal.render(summary, { width = 100, color = false })

  local out = {
    "<!doctype html>\n<html lang=\"en\" data-theme=\"auto\">\n<head>\n<meta charset=\"utf-8\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<meta name=\"color-scheme\" content=\"dark light\">\n",
    "<meta http-equiv=\"Content-Security-Policy\" content=\"", M.escape(policy), "\">\n",
    "<meta name=\"generator\" content=\"loglens ", version, "\">\n",
    "<title>", M.escape(page_title(summary)), "</title>\n",
    "<style>", style, "</style>\n</head>\n<body class=\"a-body\">\n",
    "<noscript><pre class=\"r-plain\">", M.escape(fallback), "</pre></noscript>\n",
    "<script type=\"application/json\" id=\"report-data\">", data, "</script>\n",
  }
  for _, script in ipairs(scripts) do
    out[#out + 1] = "<script>" .. script .. "</script>\n"
  end
  out[#out + 1] = "</body>\n</html>\n"
  return table.concat(out)
end

return M
