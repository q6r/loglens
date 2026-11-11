local t = require("spec.support")
local agents = require("loglens.agents")

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

-- { user agent, expected class, expected family }
local CASES = {
  -- humans
  { CHROME, "human", "Chrome" },
  { CHROME .. " Edg/120.0.0.0", "human", "Edge" },
  { CHROME .. " OPR/106.0.0.0", "human", "Opera" },
  { "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "human", "Firefox" },
  { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", "human", "Safari" },
  { "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", "human", "Safari" },
  { "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36", "human", "Chrome" },
  { "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/14.2 Chrome/87.0.4280.141 Mobile Safari/537.36", "human", "Samsung Internet" },
  { "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "human", "Internet Explorer" },
  { "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)", "human", "Internet Explorer" },
  { "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.12.388 Version/12.16", "human", "Opera" },
  { "AcmeApp/3.2 CFNetwork/1335.0.3 Darwin/21.6.0", "human", "iOS app" },
  { "Dalvik/2.1.0 (Linux; U; Android 9; SM-G960F Build/PPR1.180610.011)", "human", "Android app" },
  -- look-alikes that must stay human
  { "Mozilla/5.0 (Linux; Android 11; CUBOT KingKong) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36", "human", "Chrome" },
  { "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36 DuckDuckGo/5", "human", "Chrome" },
  { "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1 [Pinterest/iOS]", "human", "Safari" },
  { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0 YaBrowser/22.5 Yowser/2.5 Safari/537.36", "human", "Yandex Browser" },
  -- search, social, SEO, AI crawlers
  { "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot", "Googlebot" },
  { "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot", "Googlebot" },
  { "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bot", "Bingbot" },
  { "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "bot", "AhrefsBot" },
  { "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "bot", "SemrushBot" },
  { "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "bot", "Yandex" },
  { "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "bot", "Baidu Spider" },
  { "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", "bot", "DuckDuckBot" },
  { "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "bot", "Facebook" },
  { "Twitterbot/1.0", "bot", "Twitterbot" },
  { "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", "bot", "LinkedInBot" },
  { "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "bot", "Slackbot" },
  { "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)", "bot", "Discordbot" },
  { "Pinterest/0.2 (+http://www.pinterest.com/bot.html)", "bot", "Pinterest" },
  { "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot", "bot", "GPTBot" },
  { "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "bot", "ClaudeBot" },
  { "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)", "bot", "Amazonbot" },
  { "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)", "bot", "Bytespider" },
  -- monitors and automation
  { "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", "bot", "UptimeRobot" },
  { "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)", "bot", "Pingdom" },
  { "kube-probe/1.28", "bot", "Kubernetes probe" },
  { "ELB-HealthChecker/2.0", "bot", "AWS ELB health check" },
  { "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36", "bot", "Headless Chrome" },
  { "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1", "bot", "PhantomJS" },
  -- generic self-declared bots
  { "ExampleCrawler/2.0", "bot", "Other bot" },
  { "acme-spider", "bot", "Other bot" },
  { "MyBot/1.0", "bot", "Other bot" },
  { "Mozilla/5.0 (compatible; WidgetScraper)", "bot", "Other bot" },
  -- tools
  { "curl/8.4.0", "tool", "curl" },
  { "Wget/1.21.4", "tool", "Wget" },
  { "python-requests/2.31.0", "tool", "Python Requests" },
  { "Python-urllib/3.11", "tool", "Python urllib" },
  { "Go-http-client/1.1", "tool", "Go http client" },
  { "Go-http-client/2.0", "tool", "Go http client" },
  { "okhttp/4.12.0", "tool", "OkHttp" },
  { "Java/17.0.2", "tool", "Java" },
  { "Apache-HttpClient/4.5.13 (Java/11.0.11)", "tool", "Apache HttpClient" },
  { "libwww-perl/6.67", "tool", "libwww-perl" },
  { "axios/1.6.2", "tool", "axios" },
  { "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)", "tool", "node-fetch" },
  { "PostmanRuntime/7.36.0", "tool", "Postman" },
  { "Scrapy/2.11.0 (+https://scrapy.org)", "tool", "Scrapy" },
  -- scanners
  { "sqlmap/1.7.11#stable (https://sqlmap.org)", "scanner", "sqlmap" },
  { "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "scanner", "Nmap" },
  { "Mozilla/5.0 zgrab/0.x", "scanner", "ZGrab" },
  { "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)", "scanner", "Nikto" },
  { "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "scanner", "Masscan" },
  { "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "scanner", "Censys" },
  { "Fuzz Faster U Fool v2.0.0", "scanner", "ffuf" },
  { "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)", "scanner", "WPScan" },
  -- unknown
  { "-", "unknown", "(none)" },
  { "", "unknown", "(none)" },
  { "Mozilla/5.0", "unknown", "Other" },
  { "Mozilla/5.0 (compatible)", "unknown", "Other" },
  { "SomeRandomApp/1.0", "unknown", "Other" },
}

t.describe("agents.classify", function()
  t.it("classifies a table of real-world user agents", function()
    for _, case in ipairs(CASES) do
      local class, family = agents.classify(case[1])
      t.eq({ class, family }, { case[2], case[3] }, "user agent: " .. case[1])
    end
  end)

  t.it("handles nil and is case-insensitive", function()
    t.eq({ agents.classify(nil) }, { "unknown", "(none)" })
    t.eq({ agents.classify("CURL/8.0") }, { "tool", "curl" })
    t.eq({ agents.classify("GOOGLEBOT") }, { "bot", "Googlebot" })
  end)

  t.it("lets scanner names win over browser look-alikes", function()
    t.eq({ agents.classify(CHROME .. " sqlmap") }, { "scanner", "sqlmap" })
    t.eq({ agents.classify("Mozilla/5.0 (compatible; Googlebot/2.1) curl/8") }, { "bot", "Googlebot" })
  end)

  t.it("only returns known classes", function()
    local known = {}
    for _, class in ipairs(agents.CLASSES) do
      known[class] = true
    end
    for _, case in ipairs(CASES) do
      t.ok(known[(agents.classify(case[1]))])
    end
  end)

  t.it("stays fast on a pathological user agent", function()
    local started = os.clock()
    agents.classify(string.rep("Mozilla/5.0 (X11) ", 4000))
    t.lt(os.clock() - started, 0.5)
  end)
end)

t.describe("agents.new_classifier", function()
  t.it("caches results and stays bounded", function()
    local classify = agents.new_classifier(3)
    t.eq({ classify("curl/8.0") }, { "tool", "curl" })
    t.eq({ classify("curl/8.0") }, { "tool", "curl" })
    for i = 1, 20 do
      t.eq({ (classify("agent-" .. i)) }, { "unknown" })
    end
    t.eq({ classify("curl/8.0") }, { "tool", "curl" })
    t.eq({ classify(nil) }, { "unknown", "(none)" })
  end)
end)
