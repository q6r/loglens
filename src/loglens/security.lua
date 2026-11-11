--- Security heuristics over access-log records.
--
-- Everything here is a HEURISTIC over what an access log contains (method, URL, status, user
-- agent, referer, timing). It finds attempts and suspicious patterns, not compromises, and it
-- cannot see request bodies or most headers. Every finding therefore carries evidence lines and
-- explicit limitations.
--
-- Findings: `path-probing`, `path-traversal`, `sql-injection`, `xss`, `command-injection`,
-- `log4shell`, `scanner-agents`, `brute-force` and `rate-outlier`.
--
-- Nothing logged by an attacker is ever echoed raw: evidence text goes through
-- `loglens.util.defang`, which escapes control characters and neutralises markup, shell and
-- JNDI syntax. Memory is bounded: per-client state lives in Space-Saving sketches.
-- @module loglens.security
local agents = require("loglens.agents")
local time = require("loglens.time")
local topk = require("loglens.topk")
local util = require("loglens.util")

local M = {}

local byte, find, format, gmatch, gsub, lower, match, sub =
  string.byte, string.find, string.format, string.gmatch, string.gsub, string.lower, string.match,
  string.sub
local concat, sort = table.concat, table.sort
local max, min = math.max, math.min

--- Default thresholds (overridable through `Security.new`).
M.DEFAULTS = {
  capacity = 512,
  probe_min_rules = 3,
  burst_window = 300,
  burst_min_attempts = 10,
  burst_high_attempts = 50,
  rate_min_peak = 60,
  rate_min_clients = 8,
  rate_min_requests = 100,
  rate_z = 3.5,
  max_ips = 10,
  evidence_ips = 5,
  evidence_width = 110,
}

local function word_set(words)
  local set = {}
  for word in gmatch(words, "%S+") do
    set[word] = true
  end
  return set
end

---------------------------------------------------------------------------------------------
-- Payload signatures (pure functions over a request target)
---------------------------------------------------------------------------------------------

-- Percent-decodes (twice: double encoding), turns '+' into a space, replaces SQL comments with a
-- space and collapses whitespace. The input must already be lower-case.
local function normalize(text)
  if find(text, "%", 1, true) then
    text = util.percent_decode(util.percent_decode(text))
  end
  text = gsub(text, "%+", " ")
  text = gsub(text, "/%*.-%*/", " ")
  return (gsub(text, "%s+", " "))
end

-- Whether a lower-cased target holds anything worth the cost of full normalisation: a query
-- string or any character beyond plain path characters, a "..", or a well-known sensitive path
-- fragment. Plain static paths such as /css/app.css skip the scan.
local function worth_scanning(text)
  return find(text, "[^%w/%.%-_~]") ~= nil or find(text, "..", 1, true) ~= nil
    or find(text, "/etc/", 1, true) ~= nil or find(text, "/proc/", 1, true) ~= nil
    or find(text, ".ini", 1, true) ~= nil or find(text, "web-inf", 1, true) ~= nil
end

local function has_dot_dot_segment(text)
  local pos = 1
  while true do
    local at = find(text, "..", pos, true)
    if not at then
      return false
    end
    local before = at > 1 and byte(text, at - 1) or 47
    local after = byte(text, at + 2)
    -- before: start, '/', '\', '=' or space; after: end, '/', '\' or ';' (Tomcat "..;/").
    if (before == 47 or before == 92 or before == 61 or before == 32)
        and (after == nil or after == 47 or after == 92 or after == 59) then
      return true
    end
    pos = at + 1
  end
end

local SYSTEM_FILES = {
  "/etc/passwd", "/etc/shadow", "/proc/self/", "/windows/win.ini", "/winnt/win.ini", "/boot.ini",
  "/windows/system32", "/web-inf/web.xml", "c:/windows", "c:/boot.ini",
}

-- System file names count only at the start of a value or after '=', '.', '/', ':' or space, so
-- "/docs/etc/passwd-policy" is not a hit but "?file=/etc/passwd" and "../../etc/passwd" are.
local function has_system_file(text)
  text = gsub(text, "\\", "/")
  for i = 1, #SYSTEM_FILES do
    local token, pos = SYSTEM_FILES[i], 1
    while true do
      local at = find(text, token, pos, true)
      if not at then
        break
      end
      local before = at > 1 and byte(text, at - 1) or nil
      if before == nil or before == 61 or before == 46 or before == 47 or before == 58
          or before == 32 then
        return true
      end
      pos = at + 1
    end
  end
  return false
end

local WRAPPERS = {
  "php://", "expect://", "phar://", "zip://", "data://", "data:text/plain", "file://",
}

local SQL_PATTERNS = {
  { "union-select", "union[ %(]+all[ %(]+select" },
  { "union-select", "union[ %(]+distinct[ %(]+select" },
  { "union-select", "union[ %(]+select" },
  { "tautology", "%f[%w]or%f[%W] *['\"]?(%w+)['\"]? *= *['\"]?%1" },
  { "tautology", "%f[%w]and%f[%W] *['\"]?(%w+)['\"]? *= *['\"]?%1" },
  { "time-based", "sleep *%( *%d" },
  { "time-based", "benchmark *%(" },
  { "time-based", "pg_sleep *%(" },
  { "time-based", "waitfor +delay" },
  { "schema-enum", "information_schema" },
  { "schema-enum", "xp_cmdshell" },
  { "schema-enum", "load_file *%(" },
  { "schema-enum", "into +outfile" },
  { "schema-enum", "into +dumpfile" },
  { "schema-enum", "@@version" },
  { "schema-enum", "extractvalue *%(" },
  { "schema-enum", "updatexml *%(" },
  { "stacked-query", "; *drop +%w" },
  { "stacked-query", "; *shutdown" },
  { "quote-comment", "['\"] *%-%-" },
}

local XSS_TAGS = word_set(
  "script img svg iframe body object embed style meta link video audio details marquee form "
    .. "input textarea")

local XSS_EVENTS = word_set(
  "onerror onload onmouseover onmouseenter onmouseout onfocus onblur onclick ondblclick onkeydown "
    .. "onkeyup onsubmit onchange oninput onanimationstart ontoggle onpointerover onloadstart "
    .. "onpageshow onbegin")

-- Commands that are rarely innocent after a shell separator, and everyday words that only count
-- after a stronger separator.
local STRONG_COMMANDS = word_set(
  "whoami uname ifconfig ipconfig netstat nslookup wget curl nc ncat bash sh powershell cmd")
local WEAK_COMMANDS = word_set("cat ls id ping sleep pwd")
local SHELL_FOLLOWERS = {
  [""] = true, [" "] = true, [";"] = true, ["|"] = true, ["&"] = true, [")"] = true, ["$"] = true,
  ["<"] = true, [">"] = true,
}

local COMMAND_PATTERNS = {
  { "shell-path", "/bin/sh" },
  { "shell-path", "/bin/bash" },
  { "shell-path", "cmd%.exe" },
  { "shell-path", "powershell" },
  { "shell-path", "/dev/tcp/" },
  { "command-substitution", "%$%(" },
  { "command-substitution", "`[^`]+`" },
  { "download-exec", "wget +https?://" },
  { "download-exec", "curl +[%w%-]* *https?://" },
  { "php-code", "<%?php" },
  { "php-code", "eval *%(" },
  { "php-code", "base64_decode *%(" },
  { "php-code", "system *%(" },
  { "php-code", "passthru *%(" },
  { "php-code", "shell_exec *%(" },
  { "spring-classloader", "class%.module%.classloader" },
  { "spring-classloader", "class%.classloader" },
}

local function add_label(found, id, label)
  local labels = found[id]
  if not labels then
    labels = {}
    found[id] = labels
  end
  for i = 1, #labels do
    if labels[i] == label then
      return
    end
  end
  labels[#labels + 1] = label
end

-- Resolves nested Log4j lookups such as ${${::-j}${::-n}di:...} and ${lower:j}.
local function deobfuscate_lookups(text)
  for _ = 1, 4 do
    local before = text
    text = gsub(text, "%${::%-(.)}", "%1")
    text = gsub(text, "%${%a+:[^}$]-:%-([^}$])}", "%1")
    text = gsub(text, "%${%a+:%-?([^}$:])}", "%1")
    if text == before then
      break
    end
  end
  return text
end

-- Protocol of a ${jndi:...} lookup ("ldap", "rmi", ...), or nil.
local function log4shell_protocol(text)
  if not find(text, "${", 1, true) then
    return nil
  end
  local plain = deobfuscate_lookups(lower(text))
  if not find(plain, "${jndi:", 1, true) then
    return nil
  end
  return match(plain, "%${jndi:(%a+):") or "unknown"
end

local function shell_command_label(text)
  for separator, word, following in gmatch(text, "([;|`&]+) *(%a+)([^%w]?)") do
    if SHELL_FOLLOWERS[following] and separator ~= "&" then
      if STRONG_COMMANDS[word] or (WEAK_COMMANDS[word] and separator ~= "|") then
        return true
      end
    end
  end
  return false
end

--- Scans a request target (path plus query) for attack signatures.
--
-- The target is lower-cased, percent-decoded twice, `+` becomes a space and SQL comments become
-- spaces before matching, so common encodings and `UNION/**/SELECT` style evasion are covered.
-- @param target string raw request target, for example "/search?q=1%27+OR+1%3D1--"
-- @return table|nil map of finding id to a list of signature labels, or nil when nothing matched
function M.scan(target)
  local lowered = lower(target)
  if not worth_scanning(lowered) then
    return nil
  end
  local text = normalize(lowered)
  local found = {}

  if has_dot_dot_segment(text) then
    add_label(found, "path-traversal", "dot-dot-slash")
  end
  if has_system_file(text) then
    add_label(found, "path-traversal", "system-file")
  end
  for i = 1, #WRAPPERS do
    if find(text, WRAPPERS[i], 1, true) then
      add_label(found, "path-traversal", "stream-wrapper")
      break
    end
  end
  if find(text, "\0", 1, true) then
    add_label(found, "path-traversal", "null-byte")
  end

  for i = 1, #SQL_PATTERNS do
    if find(text, SQL_PATTERNS[i][2]) then
      add_label(found, "sql-injection", SQL_PATTERNS[i][1])
    end
  end

  for tag in gmatch(text, "<%s*/?%s*(%a+)") do
    if XSS_TAGS[tag] then
      add_label(found, "xss", tag == "script" and "script-tag" or "html-tag")
    end
  end
  for name in gmatch(text, "%f[%w](on%a+) *=") do
    if XSS_EVENTS[name] then
      add_label(found, "xss", "event-handler")
    end
  end
  if find(text, "javascript *:") or find(text, "vbscript *:") then
    add_label(found, "xss", "script-uri")
  end

  for i = 1, #COMMAND_PATTERNS do
    if find(text, COMMAND_PATTERNS[i][2]) then
      add_label(found, "command-injection", COMMAND_PATTERNS[i][1])
    end
  end
  if shell_command_label(text) then
    add_label(found, "command-injection", "chained-command")
  end
  if find(text, "%(%) *{") then
    add_label(found, "command-injection", "shellshock")
  end

  local protocol = log4shell_protocol(text)
  if protocol then
    add_label(found, "log4shell", protocol)
  end

  if next(found) == nil then
    return nil
  end
  return found
end

--- Scans a header value (user agent, referer) for the signatures that matter there: Log4Shell
-- lookups and Shellshock.
-- @param value string
-- @return table|nil same shape as `scan`
function M.scan_header(value)
  local found = {}
  local protocol = log4shell_protocol(value)
  if protocol then
    add_label(found, "log4shell", protocol)
  end
  if find(value, "() {", 1, true) then
    add_label(found, "command-injection", "shellshock")
  end
  if next(found) == nil then
    return nil
  end
  return found
end

---------------------------------------------------------------------------------------------
-- Probing rules
---------------------------------------------------------------------------------------------

-- id -> { category, sensitive }. A sensitive rule is reported on a single request; the others
-- only when one client trips several different rules.
local PROBE_RULES = {
  ["env-file"] = { "env-files", true },
  ["git-repo"] = { "vcs", true },
  ["svn-repo"] = { "vcs", true },
  ["hg-repo"] = { "vcs", true },
  ["ds-store"] = { "vcs", true },
  ["aws-credentials"] = { "credentials", true },
  ["ssh-keys"] = { "credentials", true },
  ["htpasswd"] = { "credentials", true },
  ["shell-history"] = { "credentials", true },
  ["wp-config"] = { "config-files", true },
  ["web-config"] = { "config-files", true },
  ["backup-file"] = { "backup-files", true },
  ["webshell"] = { "webshells", true },
  ["phpunit-rce"] = { "framework-debug", true },
  ["actuator-sensitive"] = { "framework-debug", true },
  ["wp-login"] = { "cms-admin", false },
  ["xmlrpc"] = { "cms-admin", false },
  ["wp-admin"] = { "cms-admin", false },
  ["db-admin"] = { "db-admin", false },
  ["cgi-bin"] = { "cgi-iot", false },
  ["iot-router"] = { "cgi-iot", false },
  ["actuator"] = { "framework-debug", false },
  ["server-status"] = { "framework-debug", false },
  ["phpinfo"] = { "framework-debug", false },
  ["tomcat-manager"] = { "framework-debug", false },
}

-- Exact path segment -> rule id (checked against every segment, case-insensitive).
local SEGMENTS = {
  [".env"] = "env-file",
  [".git"] = "git-repo",
  [".svn"] = "svn-repo",
  [".hg"] = "hg-repo",
  [".ds_store"] = "ds-store",
  [".aws"] = "aws-credentials",
  [".ssh"] = "ssh-keys",
  [".htpasswd"] = "htpasswd",
  [".bash_history"] = "shell-history",
  [".mysql_history"] = "shell-history",
  ["id_rsa"] = "ssh-keys",
  ["id_dsa"] = "ssh-keys",
  ["authorized_keys"] = "ssh-keys",
  ["wp-config.php"] = "wp-config",
  ["web.config"] = "web-config",
  ["wp-login.php"] = "wp-login",
  ["xmlrpc.php"] = "xmlrpc",
  ["wp-admin"] = "wp-admin",
  ["pma"] = "db-admin",
  ["myadmin"] = "db-admin",
  ["mysqladmin"] = "db-admin",
  ["adminer.php"] = "db-admin",
  ["cgi-bin"] = "cgi-bin",
  ["boaform"] = "iot-router",
  ["hnap1"] = "iot-router",
  ["gponform"] = "iot-router",
  ["setup.cgi"] = "iot-router",
  ["goform"] = "iot-router",
  ["actuator"] = "actuator",
  ["server-status"] = "server-status",
  ["server-info"] = "server-status",
  ["phpinfo.php"] = "phpinfo",
  ["eval-stdin.php"] = "phpunit-rce",
  ["backup.sql"] = "backup-file",
  ["dump.sql"] = "backup-file",
  ["db.sql"] = "backup-file",
  ["database.sql"] = "backup-file",
  ["backup.zip"] = "backup-file",
  ["backup.tar.gz"] = "backup-file",
  ["www.zip"] = "backup-file",
  ["wwwroot.zip"] = "backup-file",
  ["site.zip"] = "backup-file",
  ["web.zip"] = "backup-file",
  ["shell.php"] = "webshell",
  ["c99.php"] = "webshell",
  ["r57.php"] = "webshell",
  ["wso.php"] = "webshell",
  ["cmd.php"] = "webshell",
  ["alfa.php"] = "webshell",
  ["b374k.php"] = "webshell",
}

-- Multi-segment signatures (plain substring of the lower-cased path).
local SUBSTRINGS = {
  { "/vendor/phpunit/", "phpunit-rce" },
  { "/manager/html", "tomcat-manager" },
  { "/actuator/env", "actuator-sensitive" },
  { "/actuator/heapdump", "actuator-sensitive" },
  { "/actuator/threaddump", "actuator-sensitive" },
  { "/actuator/configprops", "actuator-sensitive" },
  { "/actuator/gateway", "actuator-sensitive" },
}

local MAX_SEGMENTS = 16

--- Classifies a request path against the probing rules.
-- @param path string request path without the query string
-- @return string|nil rule id such as "env-file" or "wp-login"
-- @return string|nil category such as "env-files" or "cms-admin"
-- @return boolean|nil sensitive true when a single request is already worth reporting
function M.probe_rule(path)
  local lowered = lower(path)
  if find(lowered, "%", 1, true) then
    lowered = util.percent_decode(lowered)
  end
  for i = 1, #SUBSTRINGS do
    if find(lowered, SUBSTRINGS[i][1], 1, true) then
      local info = PROBE_RULES[SUBSTRINGS[i][2]]
      return SUBSTRINGS[i][2], info[1], info[2]
    end
  end
  local count = 0
  for segment in gmatch(lowered, "[^/]+") do
    local rule = SEGMENTS[segment]
    if not rule then
      if sub(segment, 1, 5) == ".env." then
        rule = "env-file"
      elseif find(segment, "^phpmyadmin[%-_]?[%d%.]*$") then
        rule = "db-admin"
      end
    end
    if rule then
      local info = PROBE_RULES[rule]
      return rule, info[1], info[2]
    end
    count = count + 1
    if count >= MAX_SEGMENTS then
      break
    end
  end
  return nil
end

local LOGIN_NAMES = word_set(
  "login signin sign-in sign_in log-in logon authenticate auth session sessions token "
    .. "wp-login.php xmlrpc.php j_security_check userlogin user_login")

--- Whether a path looks like a login or authentication endpoint (last segment).
-- @param path string
-- @return boolean
function M.is_login_path(path)
  local last = match(lower(path), "([^/]+)/*$")
  return last ~= nil and LOGIN_NAMES[last] == true
end

---------------------------------------------------------------------------------------------
-- Findings
---------------------------------------------------------------------------------------------

local SEVERITY_RANK = { critical = 5, high = 4, medium = 3, low = 2, info = 1 }

local TITLES = {
  ["path-probing"] = "Probing for sensitive or admin paths",
  ["path-traversal"] = "Path traversal or local file inclusion attempts",
  ["sql-injection"] = "SQL injection signatures in URLs",
  ["xss"] = "Cross-site scripting signatures in URLs",
  ["command-injection"] = "Command or code injection signatures",
  ["log4shell"] = "Log4Shell (JNDI lookup) attempts",
  ["scanner-agents"] = "Security scanners identified by user agent",
  ["brute-force"] = "Possible brute-force or credential stuffing",
  ["rate-outlier"] = "Clients with outlier request rates",
}

local ATTEMPT_ONLY = "Heuristic: an access log shows requests, not their effect. "
  .. "A match is an attempt, not proof of compromise."

local LIMITATIONS = {
  ["path-probing"] = {
    "Name-based matching: a site that really serves these paths (for example WordPress admin "
      .. "pages) produces matches, so only clients that trigger several different probe rules, "
      .. "or any sensitive file, are reported.",
    "A 2xx answer does not prove exposure: single-page apps and catch-all routes answer every "
      .. "path with 200. Check the response body.",
    "Clients are tracked in bounded memory; low-volume scanners can be evicted on very busy logs.",
  },
  ["path-traversal"] = {
    ATTEMPT_ONLY,
    "Only the request target (path and query, first 2 KiB, decoded twice) is inspected; "
      .. "headers and request bodies are not in the log.",
    "Legitimate URLs rarely contain system file names, but documentation sites can.",
  },
  ["sql-injection"] = {
    ATTEMPT_ONLY,
    "Signature matching on the decoded URL: obfuscated payloads and POST-body injections are "
      .. "invisible to an access log.",
    "Site-search boxes can legitimately contain SQL words (someone searching for 'union select').",
  },
  ["xss"] = {
    ATTEMPT_ONLY,
    "Only the URL is inspected; stored or POST-body XSS cannot be seen in an access log.",
    "Developers testing their own site and security scanners produce the same patterns.",
  },
  ["command-injection"] = {
    ATTEMPT_ONLY,
    "Matches shell, PHP and Java-classloader syntax in the URL and Shellshock in the user agent "
      .. "or referer; payloads in other headers or bodies are not visible.",
    "Query strings that carry code snippets (a coding tutorial site, for example) can match.",
  },
  ["log4shell"] = {
    ATTEMPT_ONLY,
    "Detects ${jndi:...} lookups (including common obfuscations) in the URL, user agent and "
      .. "referer only; other headers are not logged by default.",
    "Whether the lookup worked depends on your Java dependencies, not on this log.",
  },
  ["scanner-agents"] = {
    "User agents are self-reported: scanners that pose as browsers are missed.",
    "Some matches are legitimate internet-wide research scanners, which are noisy but not "
      .. "necessarily hostile.",
  },
  ["brute-force"] = {
    "Counts 401 responses and POSTs to login-like URLs per address inside one aligned "
      .. "5-minute window; slow attacks and distributed attacks (one try per address) are not "
      .. "detected.",
    "Clients behind NAT or a shared proxy are merged, and monitoring probes with a bad "
      .. "credential look like brute force.",
    "Many login POSTs do not mean failures: successful logins are counted too.",
  },
  ["rate-outlier"] = {
    "Request rate only: CDNs, NAT gateways, monitoring and reverse proxies legitimately produce "
      .. "high rates.",
    "If every request shares one address you are probably logging a proxy's address instead of "
      .. "the client's; fix the log format or use X-Forwarded-For first.",
    "Only the busiest tracked clients are compared and per-minute peaks assume mostly "
      .. "chronological logs.",
  },
}

local Security = {}
Security.__index = Security

--- Creates a detector.
-- @param opts table|nil overrides for `M.DEFAULTS`
-- @param classifier function|nil user-agent classifier (see `agents.new_classifier`)
-- @return table
function M.new(opts, classifier)
  local o = {}
  for key, value in pairs(M.DEFAULTS) do
    o[key] = value
  end
  for key, value in pairs(opts or {}) do
    o[key] = value
  end
  return setmetatable({
    opts = o,
    classify = classifier or agents.new_classifier(),
    states = {},
    probes = topk.new(o.capacity),
    attempts = topk.new(o.capacity),
  }, Security)
end

local function plural(n, singular, many)
  return n == 1 and singular or (many or singular .. "s")
end

local function is_ok(status)
  return status >= 200 and status < 300
end

-- "GET /path?query [404]": only the log-derived parts are defanged, the status is ours.
local function sample_text(sample, width)
  return format("%s %s [%d]", util.defang(sample.method or "-", 24),
    util.defang(sample.target or "-", width), sample.status)
end

local function make_sample(e)
  local target = e.target
  if target and #target > 200 then
    target = sub(target, 1, 200)
  end
  return { ip = e.ip, method = e.method, target = target, status = e.status }
end

local function new_state(capacity)
  return {
    hits = 0,
    ok = 0,
    labels = {},
    ips = topk.new(capacity),
    samples = {},
    sample_labels = {},
  }
end

-- One request counts once per finding, however many of its signatures matched.
local function record_into(state, e, labels)
  state.hits = state.hits + 1
  if is_ok(e.status) then
    state.ok = state.ok + 1
    state.ok_sample = state.ok_sample or make_sample(e)
  end
  for _, label in ipairs(labels) do
    state.labels[label] = (state.labels[label] or 0) + 1
  end
  if not state.first or e.ts < state.first then
    state.first = e.ts
  end
  if not state.last or e.ts > state.last then
    state.last = e.ts
  end
  state.ips:add(e.ip)
  if #state.samples < 3 and not state.sample_labels[labels[1]] then
    state.sample_labels[labels[1]] = true
    state.samples[#state.samples + 1] = make_sample(e)
  end
end

function Security:record(id, e, labels)
  local state = self.states[id]
  if not state then
    state = new_state(self.opts.capacity)
    self.states[id] = state
  end
  record_into(state, e, labels)
end

function Security:record_proxy(e)
  if not self.proxies then
    self.proxies = new_state(self.opts.capacity)
  end
  record_into(self.proxies, e, { "open-proxy" })
end

function Security:record_probe(e, rule)
  local info = PROBE_RULES[rule]
  local client, fresh = self.probes:add(e.ip)
  if fresh then
    client.hits, client.rules, client.rule_count, client.sensitive = 0, {}, 0, false
    client.ok, client.first, client.last, client.categories, client.samples = 0, e.ts, e.ts, {}, {}
  end
  client.hits = client.hits + 1
  client.first, client.last = min(client.first, e.ts), max(client.last, e.ts)
  if not client.rules[rule] and client.rule_count < 16 then
    client.rules[rule], client.rule_count = true, client.rule_count + 1
  end
  client.categories[info[1]] = (client.categories[info[1]] or 0) + 1
  if info[2] then
    client.sensitive = true
    if is_ok(e.status) then
      client.ok = client.ok + 1
      client.ok_sample = client.ok_sample or make_sample(e)
    end
  end
  if #client.samples < 2 then
    client.samples[#client.samples + 1] = make_sample(e)
  end
end

function Security:record_attempt(e, denied)
  local client, fresh = self.attempts:add(e.ip)
  if fresh then
    client.total, client.denied, client.posts, client.best, client.window_count = 0, 0, 0, 0, 0
    client.first, client.last = e.ts, e.ts
  end
  client.total = client.total + 1
  if denied then
    client.denied = client.denied + 1
  else
    client.posts = client.posts + 1
  end
  client.first, client.last = min(client.first, e.ts), max(client.last, e.ts)
  local window = e.ts // self.opts.burst_window
  if client.window == window then
    client.window_count = client.window_count + 1
  else
    client.window, client.window_count = window, 1
  end
  if client.window_count > client.best then
    client.best = client.window_count
  end
end

function Security:record_all(found, e)
  for id, labels in pairs(found) do
    self:record(id, e, labels)
  end
end

--- Feeds one parsed request to every detector.
-- @param e table normalised record (see `loglens.parser.entry`)
function Security:observe(e)
  local ua = e.ua
  if ua then
    local class, family = self.classify(ua)
    if class == "scanner" then
      self:record("scanner-agents", e, { family })
    end
    local from_agent = find(ua, "[${(]") and M.scan_header(ua)
    if from_agent then
      self:record_all(from_agent, e)
    end
  end
  local referer = e.referer
  if referer and find(referer, "[${(]") then
    local from_referer = M.scan_header(referer)
    if from_referer then
      self:record_all(from_referer, e)
    end
  end

  local path = e.path
  if not path then
    return
  end
  local rule = M.probe_rule(path)
  if rule then
    self:record_probe(e, rule)
  end
  if e.proxy then
    self:record_proxy(e)
  end
  local found = M.scan(e.target)
  if found then
    self:record_all(found, e)
  end
  local denied = e.status == 401 or (e.status == 403 and M.is_login_path(path))
  if denied or (e.method == "POST" and M.is_login_path(path)) then
    self:record_attempt(e, denied)
  end
end

---------------------------------------------------------------------------------------------
-- Findings
---------------------------------------------------------------------------------------------

local function label_summary(labels, limit)
  local list = {}
  for label, count in pairs(labels) do
    list[#list + 1] = { label = label, count = count }
  end
  sort(list, function(a, b)
    if a.count ~= b.count then
      return a.count > b.count
    end
    return a.label < b.label
  end)
  local parts = {}
  for i = 1, min(limit, #list) do
    parts[i] = format("%s %d", list[i].label, list[i].count)
  end
  return concat(parts, ", ")
end

local function signature_finding(self, id, state)
  local o = self.opts
  local addresses = state.ips:len()
  local evidence = {
    format("%d matching %s from %d %s between %s and %s", state.hits,
      plural(state.hits, "request"), addresses, plural(addresses, "address", "addresses"),
      time.format_iso(state.first), time.format_iso(state.last)),
    "signatures: " .. label_summary(state.labels, 6),
  }
  local ips = {}
  for i, item in ipairs(state.ips:top(o.max_ips)) do
    ips[i] = item.key
    if i <= o.evidence_ips then
      evidence[#evidence + 1] = format("%s: %d %s", util.defang(item.key, 64), item.count,
        plural(item.count, "request"))
    end
  end
  for _, sample in ipairs(state.samples) do
    evidence[#evidence + 1] = "sample: " .. sample_text(sample, o.evidence_width)
  end
  if state.ok > 0 then
    evidence[#evidence + 1] = format("%d of these %s answered with a 2xx status, for example %s",
      state.ok, plural(state.ok, "request was", "requests were"),
      sample_text(state.ok_sample, o.evidence_width))
  end

  local severity = "medium"
  if id == "sql-injection" then
    severity = state.hits >= 25 and "high" or "medium"
  elseif id == "path-traversal" then
    severity = state.ok > 0 and "high" or "medium"
  elseif id == "xss" then
    severity = state.hits >= 10 and "medium" or "low"
  elseif id == "command-injection" or id == "log4shell" then
    severity = "high"
  end
  return {
    id = id,
    title = TITLES[id],
    severity = severity,
    count = state.hits,
    evidence = evidence,
    limitations = LIMITATIONS[id],
    ips = ips,
  }
end

-- Clients that tripped several probe rules or any sensitive rule, in rank order.
local function probers_of(self)
  local list = {}
  for _, client in ipairs(self.probes:top()) do
    if client.rule_count >= self.opts.probe_min_rules or client.sensitive then
      list[#list + 1] = client
    end
  end
  return list
end

local function probing_finding(self)
  local o = self.opts
  local probers, proxies = probers_of(self), self.proxies
  if #probers == 0 and not proxies then
    return nil
  end
  local hits, ok, widest, first, last = 0, 0, 0, nil, nil
  local categories, ips, seen = {}, {}, {}
  local ok_sample
  for _, client in ipairs(probers) do
    hits, ok = hits + client.hits, ok + client.ok
    widest = max(widest, client.rule_count)
    for category, n in pairs(client.categories) do
      categories[category] = (categories[category] or 0) + n
    end
    first = first and min(first, client.first) or client.first
    last = last and max(last, client.last) or client.last
    ok_sample = ok_sample or client.ok_sample
    seen[client.key] = true
    ips[#ips + 1] = client.key
  end
  if proxies then
    hits = hits + proxies.hits
    categories["open-proxy"] = proxies.hits
    first = first and min(first, proxies.first) or proxies.first
    last = last and max(last, proxies.last) or proxies.last
    for _, item in ipairs(proxies.ips:top()) do
      if not seen[item.key] then
        seen[item.key] = true
        ips[#ips + 1] = item.key
      end
    end
  end

  local evidence = {
    format("%d probe %s from %d %s between %s and %s", hits, plural(hits, "request"), #ips,
      plural(#ips, "address", "addresses"), time.format_iso(first), time.format_iso(last)),
    "categories: " .. label_summary(categories, 8),
  }
  for i = 1, min(#probers, o.evidence_ips) do
    local client = probers[i]
    evidence[#evidence + 1] = format("%s: %d %s across %d %s, first seen %s",
      util.defang(client.key, 64), client.hits, plural(client.hits, "probe"), client.rule_count,
      plural(client.rule_count, "rule"), time.format_iso(client.first))
  end
  local shown = 0
  for _, client in ipairs(probers) do
    for _, sample in ipairs(client.samples) do
      if shown < 3 then
        shown = shown + 1
        evidence[#evidence + 1] = "sample: " .. sample_text(sample, o.evidence_width)
      end
    end
  end
  if ok > 0 then
    evidence[#evidence + 1] = format(
      "%d sensitive-file %s answered with a 2xx status, for example %s", ok,
      plural(ok, "probe was", "probes were"), sample_text(ok_sample, o.evidence_width))
  end

  local severity = "low"
  if hits >= 25 or widest >= 5 then
    severity = "medium"
  end
  if ok > 0 then
    severity = "high"
  end
  for i = #ips, o.max_ips + 1, -1 do
    ips[i] = nil
  end
  return {
    id = "path-probing",
    title = TITLES["path-probing"],
    severity = severity,
    count = hits,
    evidence = evidence,
    limitations = LIMITATIONS["path-probing"],
    ips = ips,
  }
end

local function brute_force_finding(self)
  local o = self.opts
  local offenders, total, best = {}, 0, 0
  for _, client in ipairs(self.attempts:top()) do
    if client.best >= o.burst_min_attempts then
      offenders[#offenders + 1] = client
      total = total + client.total
      best = max(best, client.best)
    end
  end
  if #offenders == 0 then
    return nil
  end
  sort(offenders, function(a, b)
    if a.best ~= b.best then
      return a.best > b.best
    end
    return a.key < b.key
  end)
  local evidence = {
    format("%d %s made %d authentication attempts (401/403 responses or login POSTs)",
      #offenders, plural(#offenders, "address", "addresses"), total),
  }
  local ips = {}
  for i, client in ipairs(offenders) do
    if i <= o.evidence_ips then
      evidence[#evidence + 1] = format(
        "%s: %d attempts within one %d-minute window (%d denied, %d login POSTs, %d in total), "
          .. "%s to %s", util.defang(client.key, 64), client.best, o.burst_window // 60,
        client.denied, client.posts, client.total, time.format_iso(client.first),
        time.format_iso(client.last))
    end
    if i <= o.max_ips then
      ips[i] = client.key
    end
  end
  return {
    id = "brute-force",
    title = TITLES["brute-force"],
    severity = (best >= o.burst_high_attempts or total >= 100) and "high" or "medium",
    count = total,
    evidence = evidence,
    limitations = LIMITATIONS["brute-force"],
    ips = ips,
  }
end

local function rate_outlier_finding(self, context)
  local o = self.opts
  if not context or #context.ip_rates < o.rate_min_clients
      or context.requests < o.rate_min_requests then
    return nil
  end
  local clients = context.ip_rates
  local peaks = {}
  for i, client in ipairs(clients) do
    peaks[i] = client.peak
  end
  local centre, scale = util.robust_scale(peaks)
  local outliers = {}
  for _, client in ipairs(clients) do
    if client.peak >= o.rate_min_peak then
      local score
      if scale > 0 then
        score = (client.peak - centre) / scale
      else
        score = client.peak > max(1, centre) * 10 and math.huge or 0
      end
      if score >= o.rate_z then
        outliers[#outliers + 1] = client
      end
    end
  end
  if #outliers == 0 then
    return nil
  end
  sort(outliers, function(a, b)
    if a.peak ~= b.peak then
      return a.peak > b.peak
    end
    return a.key < b.key
  end)
  local evidence = {
    format("%d %s sent at least %d requests in a single minute; the typical busiest minute of "
      .. "the %d tracked clients is %s", #outliers, plural(#outliers, "client", "clients"),
      o.rate_min_peak, #clients, util.fmt_int(centre)),
  }
  local ips = {}
  for i, client in ipairs(outliers) do
    if i <= o.evidence_ips then
      evidence[#evidence + 1] = format("%s: up to %s requests in one minute (%s in total)",
        util.defang(client.key, 64), util.fmt_int(client.peak), util.fmt_int(client.count))
    end
    if i <= o.max_ips then
      ips[i] = client.key
    end
  end
  return {
    id = "rate-outlier",
    title = TITLES["rate-outlier"],
    severity = "low",
    count = #outliers,
    evidence = evidence,
    limitations = LIMITATIONS["rate-outlier"],
    ips = ips,
  }
end

--- Builds the findings, most severe first (ties by id).
-- @param context table|nil `{ ip_rates = Stats:ip_rates(), requests = total requests }`; needed
--   only for the rate-outlier heuristic
-- @return table[] findings `{ id, title, severity, count, evidence[], limitations[], ips[] }`
function Security:findings(context)
  local list = {}
  local probing = probing_finding(self)
  if probing then
    list[#list + 1] = probing
  end
  for _, id in ipairs({ "path-traversal", "sql-injection", "xss", "command-injection",
    "log4shell", "scanner-agents" }) do
    local state = self.states[id]
    if state then
      list[#list + 1] = signature_finding(self, id, state)
    end
  end
  local brute = brute_force_finding(self)
  if brute then
    list[#list + 1] = brute
  end
  local outliers = rate_outlier_finding(self, context)
  if outliers then
    list[#list + 1] = outliers
  end
  sort(list, function(a, b)
    if a.severity ~= b.severity then
      return SEVERITY_RANK[a.severity] > SEVERITY_RANK[b.severity]
    end
    return a.id < b.id
  end)
  return list
end

return M
