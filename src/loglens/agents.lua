--- User-agent classification: human, bot, tool, scanner or unknown.
--
-- The classification is name based and deliberately conservative. It uses an ordered table
-- (first match wins, case-insensitive substring) so specific products are recognised before the
-- generic "Mozilla/5.0" prefix that crawlers copy from browsers:
--
--   1. scanner  security tools and internet-wide research scanners (sqlmap, nikto, zgrab ...)
--   2. bot      search/social/SEO/AI crawlers, monitors, headless browsers
--   3. tool     HTTP libraries and command line clients (curl, python-requests ...)
--   4. generic  anything calling itself a bot, crawler, spider or scraper
--   5. human    browser engines (Chrome, Firefox, Safari, Edge, Opera, IE ...)
--   6. unknown  empty, "-" or unrecognised
--
-- A user agent is an unauthenticated, self-reported string: anyone can claim to be Googlebot or
-- Chrome. Treat the result as a hint, not as proof of identity.
-- @module loglens.agents
local M = {}

local find, lower = string.find, string.lower

--- All classes in display order.
M.CLASSES = { "human", "bot", "tool", "scanner", "unknown" }

local SCANNERS = {
  { "sqlmap", "sqlmap" },
  { "nikto", "Nikto" },
  { "masscan", "Masscan" },
  { "zgrab", "ZGrab" },
  { "nmap", "Nmap" },
  { "acunetix", "Acunetix" },
  { "netsparker", "Netsparker" },
  { "wpscan", "WPScan" },
  { "dirbuster", "DirBuster" },
  { "gobuster", "Gobuster" },
  { "feroxbuster", "Feroxbuster" },
  { "fuzz faster u fool", "ffuf" },
  { "ffuf", "ffuf" },
  { "wfuzz", "Wfuzz" },
  { "nuclei", "Nuclei" },
  { "openvas", "OpenVAS" },
  { "nessus", "Nessus" },
  { "w3af", "w3af" },
  { "arachni", "Arachni" },
  { "havij", "Havij" },
  { "zmeu", "ZmEu" },
  { "skipfish", "Skipfish" },
  { "commix", "Commix" },
  { "jorgee", "Jorgee" },
  { "burpcollaborator", "Burp Collaborator" },
  { "censys", "Censys" },
  { "shodan", "Shodan" },
  { "l9explore", "LeakIX" },
  { "l9scan", "LeakIX" },
  { "expanse", "Expanse" },
}

local BOTS = {
  { "googlebot", "Googlebot" },
  { "adsbot-google", "Google AdsBot" },
  { "mediapartners-google", "Google AdSense" },
  { "google-inspectiontool", "Google Inspection Tool" },
  { "googleother", "GoogleOther" },
  { "apis-google", "Google APIs" },
  { "feedfetcher-google", "Google Feedfetcher" },
  { "google-read-aloud", "Google Read Aloud" },
  { "storebot-google", "Google Storebot" },
  { "bingbot", "Bingbot" },
  { "bingpreview", "Bing Preview" },
  { "msnbot", "MSNBot" },
  { "slurp", "Yahoo Slurp" },
  { "duckduckbot", "DuckDuckBot" },
  { "baiduspider", "Baidu Spider" },
  { "yandex.com/bots", "Yandex" },
  { "yandexbot", "Yandex" },
  { "yandeximages", "Yandex" },
  { "sogou web spider", "Sogou" },
  { "exabot", "Exabot" },
  { "ia_archiver", "Internet Archive" },
  { "archive.org_bot", "Internet Archive" },
  { "applebot", "Applebot" },
  { "facebookexternalhit", "Facebook" },
  { "facebot", "Facebook" },
  { "meta-externalagent", "Meta" },
  { "meta-externalfetcher", "Meta" },
  { "twitterbot", "Twitterbot" },
  { "linkedinbot", "LinkedInBot" },
  { "pinterest.com/bot", "Pinterest" },
  { "pinterestbot", "Pinterest" },
  { "slackbot", "Slackbot" },
  { "slack-imgproxy", "Slack" },
  { "telegrambot", "TelegramBot" },
  { "whatsapp", "WhatsApp" },
  { "discordbot", "Discordbot" },
  { "skypeuripreview", "Skype URI Preview" },
  { "ahrefs", "AhrefsBot" },
  { "semrush", "SemrushBot" },
  { "mj12bot", "MJ12bot" },
  { "dotbot", "DotBot" },
  { "blexbot", "BLEXBot" },
  { "petalbot", "PetalBot" },
  { "seznambot", "SeznamBot" },
  { "dataforseobot", "DataForSEO" },
  { "screaming frog", "Screaming Frog" },
  { "sistrix", "Sistrix" },
  { "serpstatbot", "Serpstat" },
  { "rogerbot", "Moz Rogerbot" },
  { "gptbot", "GPTBot" },
  { "chatgpt-user", "ChatGPT-User" },
  { "oai-searchbot", "OAI-SearchBot" },
  { "claudebot", "ClaudeBot" },
  { "claude-web", "Claude-Web" },
  { "anthropic-ai", "Anthropic" },
  { "perplexitybot", "PerplexityBot" },
  { "ccbot", "CCBot" },
  { "amazonbot", "Amazonbot" },
  { "bytespider", "Bytespider" },
  { "diffbot", "Diffbot" },
  { "uptimerobot", "UptimeRobot" },
  { "pingdom", "Pingdom" },
  { "statuscake", "StatusCake" },
  { "site24x7", "Site24x7" },
  { "newrelicpinger", "New Relic" },
  { "datadog", "Datadog" },
  { "zabbix", "Zabbix" },
  { "nagios", "Nagios" },
  { "blackbox exporter", "Prometheus Blackbox" },
  { "prometheus", "Prometheus" },
  { "kube-probe", "Kubernetes probe" },
  { "elb-healthchecker", "AWS ELB health check" },
  { "googlehc", "Google health check" },
  { "uptime-kuma", "Uptime Kuma" },
  { "gtmetrix", "GTmetrix" },
  { "chrome-lighthouse", "Lighthouse" },
  { "pagespeed", "PageSpeed" },
  { "headlesschrome", "Headless Chrome" },
  { "phantomjs", "PhantomJS" },
  { "puppeteer", "Puppeteer" },
  { "playwright", "Playwright" },
  { "selenium", "Selenium" },
  { "feedly", "Feedly" },
  { "inoreader", "Inoreader" },
  { "newsblur", "NewsBlur" },
}

local TOOLS = {
  { "curl/", "curl" },
  { "wget/", "Wget" },
  { "python-requests", "Python Requests" },
  { "python-urllib", "Python urllib" },
  { "python-httpx", "Python httpx" },
  { "aiohttp", "aiohttp" },
  { "go-http-client", "Go http client" },
  { "okhttp", "OkHttp" },
  { "apache-httpclient", "Apache HttpClient" },
  { "jakarta commons-httpclient", "Apache HttpClient" },
  { "java/", "Java" },
  { "libwww-perl", "libwww-perl" },
  { "mechanize", "Mechanize" },
  { "scrapy", "Scrapy" },
  { "node-fetch", "node-fetch" },
  { "axios/", "axios" },
  { "sindresorhus/got", "got" },
  { "undici", "undici" },
  { "postmanruntime", "Postman" },
  { "insomnia", "Insomnia" },
  { "httpie", "HTTPie" },
  { "faraday", "Faraday" },
  { "guzzlehttp", "Guzzle" },
  { "reqwest", "reqwest" },
  { "fasthttp", "fasthttp" },
  { "colly", "Colly" },
  { "dart:io", "Dart" },
}

-- Product tokens that identify a browser family, most specific first (Edge and Opera also
-- contain "Chrome/" and "Safari/").
local BROWSERS = {
  { "edg/", "Edge" },
  { "edga/", "Edge" },
  { "edgios/", "Edge" },
  { "edge/", "Edge" },
  { "opr/", "Opera" },
  { "opera", "Opera" },
  { "vivaldi", "Vivaldi" },
  { "samsungbrowser", "Samsung Internet" },
  { "yabrowser", "Yandex Browser" },
  { "ucbrowser", "UC Browser" },
  { "firefox/", "Firefox" },
  { "fxios", "Firefox" },
  { "chrome/", "Chrome" },
  { "crios", "Chrome" },
  { "chromium", "Chromium" },
  { "safari/", "Safari" },
  { "trident/", "Internet Explorer" },
  { "msie ", "Internet Explorer" },
  { "cfnetwork/", "iOS app" },
  { "dalvik/", "Android app" },
}

-- Lua patterns for products that merely call themselves a bot (checked after the named tables).
local GENERIC = {
  "bot/",
  "bot;",
  "bot%)",
  "bot$",
  "crawl",
  "spider",
  "scraper",
}

local function first_match(ua, rules)
  for i = 1, #rules do
    local rule = rules[i]
    if find(ua, rule[1], 1, true) then
      return rule[2]
    end
  end
  return nil
end

--- Classifies one user-agent string (uncached; see `new_classifier`).
-- @param ua string|nil
-- @return string class, one of `M.CLASSES`
-- @return string family name such as "Googlebot", "curl", "Chrome" or "(none)"
function M.classify(ua)
  if ua == nil or ua == "" or ua == "-" then
    return "unknown", "(none)"
  end
  local lowered = lower(ua)
  local name = first_match(lowered, SCANNERS)
  if name then
    return "scanner", name
  end
  name = first_match(lowered, BOTS)
  if name then
    return "bot", name
  end
  name = first_match(lowered, TOOLS)
  if name then
    return "tool", name
  end
  for i = 1, #GENERIC do
    if find(lowered, GENERIC[i]) then
      return "bot", "Other bot"
    end
  end
  if find(lowered, "mozilla/", 1, true) or find(lowered, "opera/", 1, true) then
    name = first_match(lowered, BROWSERS)
    if name then
      return "human", name
    end
  elseif find(lowered, "cfnetwork/", 1, true) or find(lowered, "dalvik/", 1, true) then
    return "human", first_match(lowered, BROWSERS)
  end
  return "unknown", "Other"
end

--- Creates a classifier function with a private, size-bounded cache (user agents repeat heavily).
-- @param cache_limit number|nil maximum cached strings before the cache is reset (default 4096)
-- @return function `classify(ua) -> class, family`
function M.new_classifier(cache_limit)
  cache_limit = cache_limit or 4096
  local cache, size = {}, 0
  return function(ua)
    local hit = cache[ua or ""]
    if hit then
      return hit[1], hit[2]
    end
    local class, name = M.classify(ua)
    if size >= cache_limit then
      cache, size = {}, 0
    end
    cache[ua or ""] = { class, name }
    size = size + 1
    return class, name
  end
end

return M
