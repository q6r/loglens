rockspec_format = "3.0"
package = "loglens"
version = "0.1.0-1"

source = {
  url = "git+https://github.com/q6r/loglens.git",
  tag = "v0.1.0",
}

description = {
  summary = "Web-server log analyzer: live terminal dashboard, JSON summary and offline HTML report",
  detailed = [[
    loglens reads nginx, Apache and Caddy access logs (combined, common, JSON lines) and turns them
    into an animated terminal dashboard, a machine-readable summary and a self-contained HTML
    report. Memory use is bounded whatever the size of the log, and a set of security heuristics
    (scanners, path traversal, SQL injection and XSS probes, brute force) comes with evidence and
    stated limitations. Pure Lua, no dependencies.
  ]],
  homepage = "https://github.com/q6r/loglens",
  license = "MIT",
  labels = { "logs", "nginx", "apache", "caddy", "analytics", "terminal", "security" },
}

dependencies = {
  "lua >= 5.3",
}

test = {
  type = "command",
  command = "lua spec/run.lua",
}

build = {
  type = "builtin",
  modules = {
    ["loglens.agents"] = "src/loglens/agents.lua",
    ["loglens.analyzer"] = "src/loglens/analyzer.lua",
    ["loglens.args"] = "src/loglens/args.lua",
    ["loglens.cli"] = "src/loglens/cli.lua",
    ["loglens.histogram"] = "src/loglens/histogram.lua",
    ["loglens.hll"] = "src/loglens/hll.lua",
    ["loglens.json"] = "src/loglens/json.lua",
    ["loglens.lines"] = "src/loglens/lines.lua",
    ["loglens.parser"] = "src/loglens/parser/init.lua",
    ["loglens.parser.caddy"] = "src/loglens/parser/caddy.lua",
    ["loglens.parser.combined"] = "src/loglens/parser/combined.lua",
    ["loglens.parser.entry"] = "src/loglens/parser/entry.lua",
    ["loglens.parser.json"] = "src/loglens/parser/json.lua",
    ["loglens.platform"] = "src/loglens/platform.lua",
    ["loglens.render.html"] = "src/loglens/render/html.lua",
    ["loglens.render.terminal"] = "src/loglens/render/terminal.lua",
    ["loglens.security"] = "src/loglens/security.lua",
    ["loglens.sha256"] = "src/loglens/sha256.lua",
    ["loglens.stats"] = "src/loglens/stats.lua",
    ["loglens.summary"] = "src/loglens/summary.lua",
    ["loglens.tail"] = "src/loglens/tail.lua",
    ["loglens.time"] = "src/loglens/time.lua",
    ["loglens.topk"] = "src/loglens/topk.lua",
    ["loglens.util"] = "src/loglens/util.lua",
    ["loglens.version"] = "src/loglens/version.lua",
    ["loglens.watch"] = "src/loglens/watch.lua",
  },
  install = {
    bin = { loglens = "bin/loglens" },
    -- The HTML report reads these next to the modules; one folder per file (see render/html.lua).
    lua = {
      ["loglens.assets.aurora_css"] = "src/loglens/assets/aurora.css",
      ["loglens.assets.aurora_js"] = "src/loglens/assets/aurora.js",
      ["loglens.assets.aurora-charts_js"] = "src/loglens/assets/aurora-charts.js",
      ["loglens.assets.report_css"] = "src/loglens/assets/report.css",
      ["loglens.assets.report_js"] = "src/loglens/assets/report.js",
    },
  },
  copy_directories = { "docs", "examples" },
}
