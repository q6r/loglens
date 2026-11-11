local t = require("spec.support")
local analyzer = require("loglens.analyzer")
local html = require("loglens.render.html")
local json = require("loglens.json")
local loggen = require("tools.loggen")
local sha256 = require("loglens.sha256")
local summary_module = require("loglens.summary")

local LS = "\226\128\168" -- U+2028
local PS = "\226\128\169" -- U+2029
local HOSTILE = "</script><img src=x onerror=alert(1)>"

local function sample_summary()
  local lines = loggen.lines({ seed = 11, count = 150 })
  return analyzer.analyze_lines(lines, { sources = { "access.log" }, now = 1794400000 })
end

-- Everything between the opening tag of the JSON island and the first closing script tag.
local function island_of(document)
  return document:match('<script type="application/json" id="report%-data">(.-)</script>')
end

local function count_of(text, needle)
  local count, position = 0, 1
  while true do
    local found = text:find(needle, position, true)
    if not found then
      return count
    end
    count, position = count + 1, found + #needle
  end
end

-- A summary whose every kind of untrusted string carries the hostile text.
local function hostile_summary()
  local summary = sample_summary()
  summary.meta.sources = { HOSTILE .. LS .. PS }
  summary.paths[1].path = "/" .. HOSTILE .. LS .. "&amp;" .. PS
  summary.clients[1].ip = HOSTILE
  summary.referrers[1].host = HOSTILE
  summary.agents.families[1].name = HOSTILE
  summary.agents.top[1].agent = HOSTILE .. LS
  summary.errorPaths.notFound[1].path = HOSTILE
  summary.meta.malformedSamples = { { line = 1, reason = HOSTILE, preview = HOSTILE .. PS } }
  summary.findings[1].title = HOSTILE
  summary.findings[1].evidence = { HOSTILE, "sample: GET /" .. HOSTILE .. " [200]" }
  summary.findings[1].limitations = { HOSTILE .. LS }
  summary.findings[1].ips = { HOSTILE }
  summary.latency.slowest[1].path = HOSTILE
  return summary
end

t.describe("html.island", function()
  t.it("escapes the five characters that could end the script or the string", function()
    t.eq(html.island("<>&"), "\\u003c\\u003e\\u0026")
    t.eq(html.island("a" .. LS .. "b" .. PS .. "c"), "a\\u2028b\\u2029c")
    t.eq(html.island('{"k":"v"}'), '{"k":"v"}')
    t.eq(html.island(html.island("</script>")), html.island("</script>"), "applying it twice changes nothing more")
  end)

  t.it("keeps the JSON valid and restores the original text", function()
    local original = { text = "</script><!-- & > <" .. LS .. PS .. "end", list = { "<b>", "a&b" } }
    local safe = html.island(json.encode(original))
    t.not_contains(safe, "<")
    t.not_contains(safe, ">")
    t.not_contains(safe, "&")
    t.not_contains(safe, LS)
    t.not_contains(safe, PS)
    t.eq(json.decode(safe), original)
  end)

  t.it("is stable for arbitrary strings (property)", function()
    local alphabet = { "<", ">", "&", LS, PS, "/", "script", "\"", "\\", "\n", "a", "\226\130\172", "\0" }
    local state = 4242
    for _ = 1, 200 do
      local parts = {}
      for i = 1, state % 12 + 1 do
        state = (state * 1103515245 + 12345) % 2147483648
        parts[i] = alphabet[state % #alphabet + 1]
      end
      state = (state * 1103515245 + 12345) % 2147483648
      local original = { s = table.concat(parts) }
      local safe = html.island(json.encode(original))
      t.is_nil(safe:find("[<>&]"))
      t.is_nil(safe:find(LS, 1, true))
      t.eq(json.decode(safe), original)
    end
  end)
end)

t.describe("html.escape", function()
  t.it("escapes markup and quotes", function()
    t.eq(html.escape([[<a href="x" onclick='y'>&]]), "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;")
    t.eq(html.escape("plain"), "plain")
  end)
end)

t.describe("html.render", function()
  local summary = sample_summary()
  local document = assert(html.render(summary))

  t.it("produces one self-contained HTML document", function()
    t.eq(document:sub(1, 15), "<!doctype html>")
    t.eq(document:sub(-8), "</html>\n")
    t.eq(count_of(document, "<html "), 1)
    t.eq(count_of(document, "<body"), 1)
    t.contains(document, "<title>loglens report - access.log</title>")
    t.contains(document, "<noscript>")
    t.ge(#document, 150000)
    t.lt(#document, 400000, "the report stays a reasonable size")
  end)

  t.it("leaves the layout to the report script: the body holds only the fallback, the data and the scripts", function()
    local body = document:match('<body class="a%-body">\n(.*)</body>')
    t.ok(body, "the body carries the Aurora body class")
    local rest = body
      :gsub('<script type="application/json".-</script>', "")
      :gsub("<script>.-</script>", "")
      :gsub("<noscript>.-</noscript>", "")
    t.eq((rest:gsub("%s", "")), "", "no static header, navigation or container")
    t.not_contains(document, '<header class="a-topbar">')
    t.not_contains(document, 'id="app"')
  end)

  t.it("builds the navigation rail from the report's sections", function()
    t.contains(document, "Aurora.shell({")
    for _, id in ipairs({ "overview", "traffic", "content", "clients", "security", "data" }) do
      t.contains(document, "{ id: '" .. id .. "', label:", "the report script declares the " .. id .. " section")
    end
  end)

  t.it("embeds the summary as JSON that decodes to the same document", function()
    local island = island_of(document)
    local copy = json.decode(island)
    t.is_true(summary_module.validate(copy))
    t.eq(copy.totals, json.decode(summary_module.encode(summary)).totals)
    t.eq(copy.findings[1].id, summary.findings[1].id)
  end)

  t.it("falls back to the terminal dashboard without JavaScript", function()
    local fallback = document:match('<noscript><pre class="r%-plain">(.-)</pre></noscript>')
    t.ok(fallback)
    t.contains(fallback, "REQUESTS")
    t.contains(fallback, "FINDINGS")
    t.not_contains(fallback, "\27")
  end)

  t.it("makes no external requests and loads nothing from elsewhere", function()
    local without_data = document:gsub('<script type="application/json".-</script>', ""):gsub("<noscript>.-</noscript>", "")
    for url in without_data:gmatch("https?://[^%s\"'<>)]+") do
      t.eq(url, "http://www.w3.org/2000/svg", "only the SVG namespace is mentioned")
    end
    for _, forbidden in ipairs({ "<link ", "<img", "<iframe", "<form", "@import", "<base", "src=\"http", "href=\"http" }) do
      t.not_contains(without_data, forbidden)
    end
  end)

  t.it("pins every inline script and style in its Content-Security-Policy", function()
    local policy = document:match('http%-equiv="Content%-Security%-Policy" content="(.-)">'):gsub("&#39;", "'")
    t.contains(policy, "default-src 'none'")
    t.contains(policy, "base-uri 'none'")
    t.contains(policy, "form-action 'none'")
    t.not_contains(policy, "unsafe-inline")
    t.not_contains(policy, "unsafe-eval")
    local scripts = 0
    for body in document:gmatch("<script>(.-)</script>") do
      scripts = scripts + 1
      t.contains(policy, sha256.csp_source(body), "script " .. scripts .. " is pinned")
    end
    t.eq(scripts, 3, "the UI kit, its charts and the report view")
    local style = document:match("<style>(.-)</style>")
    t.contains(policy, "style-src " .. sha256.csp_source(style))
  end)

  t.it("is deterministic", function()
    t.eq(assert(html.render(summary)), document)
  end)

  t.it("does not alter the summary", function()
    local before = summary_module.encode(summary)
    html.render(summary)
    t.eq(summary_module.encode(summary), before)
  end)

  t.it("renders an empty log", function()
    local empty = analyzer.analyze_lines({}, { format = "combined", now = 1794400000 })
    local page = assert(html.render(empty))
    t.contains(page, "<title>loglens report</title>")
    t.is_true(summary_module.validate(json.decode(island_of(page))))
  end)

  t.it("rejects what is not a summary", function()
    local page, err = html.render({ schema = "something else" })
    t.is_nil(page)
    t.contains(err, "invalid summary")
    t.eq(select(2, html.render(nil)), "invalid summary: $: expected a table, got nil")
  end)

  t.it("explains a missing asset", function()
    local page, err = html.render(summary, { assets_dir = "no/such/directory" })
    t.is_nil(page)
    t.contains(err, "cannot read the report asset")
    t.contains(err, "aurora.css")
  end)
end)

t.describe("the report view (report.js and report.css)", function()
  local view = assert(t.read_file(t.root .. "src/loglens/assets/report.js"))
  local style = assert(t.read_file(t.root .. "src/loglens/assets/report.css"))

  t.it("never builds markup or code from data", function()
    for _, forbidden in ipairs({
      "innerHTML",
      "outerHTML",
      "insertAdjacentHTML",
      "document.write",
      "eval(",
      "new Function",
      "srcdoc",
    }) do
      t.not_contains(view, forbidden)
    end
  end)

  t.it("sets no inline style and names no external address", function()
    t.not_contains(view, "style=")
    t.not_contains(view, "setAttribute('style'")
    t.not_contains(view, "cssText")
    t.is_nil(view:find("https?://"), "no external address in report.js")
    t.is_nil(style:find("https?://"), "no external address in report.css")
    t.is_nil(style:find("@import", 1, true), "no import in report.css")
    t.is_nil(style:find("url(", 1, true), "no url() in report.css")
  end)

  t.it("takes its colours from the UI kit's custom properties", function()
    t.is_nil(style:find("#%x%x%x"), "no hex colour in report.css")
    t.is_nil(style:find("rgba?%("), "no rgb() colour in report.css")
    t.is_nil(view:find("#%x%x%x%x%x%x"), "no hex colour in report.js")
  end)
end)

t.describe("html.render with hostile data", function()
  local summary = hostile_summary()
  local document = assert(html.render(summary))

  t.it("never lets log text close the script element or start a comment", function()
    t.eq(count_of(document:lower(), "</script"), 4, "the data island and the three real scripts, nothing else")
    local island = island_of(document)
    t.ok(island and #island > 1000)
    t.not_contains(island, "<")
    t.not_contains(island, ">")
    t.not_contains(island, "&")
    t.not_contains(island, LS)
    t.not_contains(island, PS)
    t.not_contains(island, "<!--")
  end)

  t.it("restores the hostile text exactly after JSON.parse", function()
    local copy = json.decode(island_of(document))
    t.eq(copy.meta.sources[1], HOSTILE .. LS .. PS)
    t.eq(copy.paths[1].path, "/" .. HOSTILE .. LS .. "&amp;" .. PS)
    t.eq(copy.findings[1].title, HOSTILE)
    t.eq(copy.findings[1].evidence[1], HOSTILE)
    t.eq(copy.agents.top[1].agent, HOSTILE .. LS)
    t.eq(copy.meta.malformedSamples[1].preview, HOSTILE .. PS)
  end)

  t.it("escapes the title and the plain-text fallback", function()
    t.contains(document, "<title>loglens report - ")
    local title = document:match("<title>(.-)</title>")
    t.not_contains(title, "<")
    t.not_contains(title, ">")
    local fallback = document:match('<noscript><pre class="r%-plain">(.-)</pre></noscript>')
    t.not_contains(fallback, "<")
    t.not_contains(fallback, ">")
    t.not_contains(document, "<img src=x")
    t.not_contains(document, "onerror=alert(1)>")
  end)

  t.it("survives hostile log lines end to end", function()
    local lines = {
      '203.0.113.5 - - [10/Nov/2026:14:00:00 +0000] "GET /</script><img/src=x/onerror=alert(1)> HTTP/1.1" 404 10 '
        .. '"https://x.example/</script>" "</script><img src=x onerror=alert(1)>' .. LS .. ' agent"',
      '203.0.113.6 - - [10/Nov/2026:14:00:01 +0000] "GET /?q=1%27%20UNION%20SELECT%20password%20FROM%20users--'
        .. '</script> HTTP/1.1" 200 10 "-" "sqlmap/1.7 </script>"',
      "</script><img src=x onerror=alert(1)>" .. LS,
    }
    local page = assert(html.render(analyzer.analyze_lines(lines, { sources = { "</script>.log" }, now = 1794400000 })))
    t.eq(count_of(page:lower(), "</script"), 4)
    local island = island_of(page)
    t.is_nil(island:find("[<>&]"))
    t.is_nil(island:find(LS, 1, true))
    t.is_true(summary_module.validate(json.decode(island)))
  end)
end)
