local t = require("spec.support")
local parser = require("loglens.parser")
local entry = require("loglens.parser.entry")
local lcg = require("tools.lcg")
local time = require("loglens.time")

local combined = parser.get("combined")
local common = parser.get("common")

local function parsed(parse, line)
  local record, reason = parse(line)
  t.ok(record, "expected a record for " .. t.inspect(line) .. " but got: " .. tostring(reason))
  return record
end

local function rejected(parse, line, reason_fragment)
  local record, reason = parse(line)
  t.is_nil(record, "expected rejection of " .. t.inspect(line))
  t.ok(reason, "a reason is required")
  if reason_fragment then
    t.contains(reason, reason_fragment)
  end
end

local STAMP = '[10/Nov/2026:14:03:09 +0200]'
local EPOCH = time.parse_iso("2026-11-10T12:03:09Z")

t.describe("combined parser: well-formed lines", function()
  t.it("parses the canonical Apache common example", function()
    local r = parsed(common, '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326')
    t.eq(r.ip, "127.0.0.1")
    t.eq(r.ts, 971211336)
    t.eq(r.method, "GET")
    t.eq(r.target, "/apache_pb.gif")
    t.eq(r.path, "/apache_pb.gif")
    t.is_nil(r.query)
    t.eq(r.proto, "HTTP/1.0")
    t.eq(r.status, 200)
    t.eq(r.bytes, 2326)
    t.is_nil(r.referer)
    t.is_nil(r.ua)
    t.is_nil(r.extended)
  end)

  t.it("parses a full nginx combined line with timings", function()
    local line = '203.0.113.9 - - ' .. STAMP .. ' "GET /a/b?c=1&d=2 HTTP/1.1" 200 512 '
      .. '"https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0" 0.123 0.100'
    local r = parsed(combined, line)
    t.eq(r.ip, "203.0.113.9")
    t.eq(r.ts, EPOCH)
    t.eq(r.path, "/a/b")
    t.eq(r.query, "c=1&d=2")
    t.eq(r.target, "/a/b?c=1&d=2")
    t.eq(r.referer, "https://example.com/start")
    t.eq(r.ua, "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0")
    t.is_true(r.extended)
    t.near(r.rt, 0.123, 1e-9)
    t.near(r.urt, 0.1, 1e-9)
    t.eq(math.type(r.status), "integer")
    t.eq(math.type(r.bytes), "integer")
    t.eq(math.type(r.ts), "integer")
  end)

  t.it("treats dashes as missing values", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 304 - "-" "-"')
    t.eq(r.bytes, 0)
    t.is_nil(r.referer)
    t.is_nil(r.ua)
    t.is_true(r.extended)
    t.eq(r.status, 304)
  end)

  t.it("supports IPv6, IPv4-mapped and zone-id clients", function()
    for _, ip in ipairs({ "2001:db8::1", "::1", "::ffff:192.0.2.1", "fe80::1%eth0", "2001:0db8:85a3:0000:0000:8a2e:0370:7334" }) do
      local r = parsed(combined, ip .. ' - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 1 "-" "-"')
      t.eq(r.ip, ip)
    end
  end)

  t.it("strips a client port and understands Apache vhost prefixes", function()
    local r = parsed(combined, '203.0.113.5:51234 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 1 "-" "-"')
    t.eq(r.ip, "203.0.113.5")
    local v = parsed(combined, 'example.com:443 203.0.113.7 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 1 "-" "-"')
    t.eq(v.ip, "203.0.113.7")
    local v2 = parsed(combined, '203.0.113.1:80 198.51.100.2 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 1')
    t.eq(v2.ip, "198.51.100.2")
  end)

  t.it("accepts user names with spaces", function()
    local r = parsed(combined, '1.2.3.4 - John Smith ' .. STAMP .. ' "GET / HTTP/1.1" 200 1')
    t.eq(r.ip, "1.2.3.4")
    t.eq(r.status, 200)
  end)

  t.it("honours the time zone", function()
    local r = parsed(combined, '1.2.3.4 - - [10/Nov/2026:05:33:09 -0630] "GET / HTTP/1.1" 200 1')
    t.eq(r.ts, EPOCH)
  end)

  t.it("handles every method shape", function()
    local options = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "OPTIONS * HTTP/1.1" 200 0')
    t.eq({ options.method, options.path }, { "OPTIONS", "*" })
    local lower = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "get /x HTTP/1.1" 200 0')
    t.eq(lower.method, "get")
    local propfind = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "PROPFIND /dav HTTP/1.1" 207 0')
    t.eq(propfind.method, "PROPFIND")
    local old = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /legacy" 200 0')
    t.eq({ old.method, old.path, old.proto }, { "GET", "/legacy", nil })
    local h2 = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /x HTTP/2.0" 200 0')
    t.eq(h2.proto, "HTTP/2.0")
  end)

  t.it("flags proxy-style requests and splits absolute URIs", function()
    local connect = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "CONNECT example.com:443 HTTP/1.1" 400 0')
    t.is_true(connect.proxy)
    t.eq(connect.path, "example.com:443")
    local absolute = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET http://example.com/x?y=1 HTTP/1.1" 404 0')
    t.is_true(absolute.proxy)
    t.eq({ absolute.path, absolute.query }, { "/x", "y=1" })
    local bare = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET http://example.com HTTP/1.1" 404 0')
    t.eq(bare.path, "/")
    local plain = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /x HTTP/1.1" 200 0')
    t.is_nil(plain.proxy)
  end)

  t.it("splits query strings and fragments", function()
    local r = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /a?b=1?c#frag HTTP/1.1" 200 0')
    t.eq({ r.path, r.query }, { "/a", "b=1?c" })
    local f = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /a#frag HTTP/1.1" 200 0')
    t.eq({ f.path, f.query }, { "/a", nil })
    local empty = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /a? HTTP/1.1" 200 0')
    t.eq({ empty.path, empty.query }, { "/a", nil })
  end)

  t.it("keeps unencoded spaces in the target", function()
    local r = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "GET /a b/c d.html HTTP/1.1" 404 0')
    t.eq(r.target, "/a b/c d.html")
  end)

  t.it("tolerates surrounding whitespace, CRLF and brackets inside fields", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET /a[1] HTTP/1.1" 200 5 "-" "Mozilla [en] x"\r')
    t.eq(r.ua, "Mozilla [en] x")
    t.eq(r.path, "/a[1]")
    local timed = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "UA" 0.5\r')
    t.near(timed.rt, 0.5, 1e-9)
  end)
end)

t.describe("combined parser: quoting and escapes", function()
  t.it("decodes escaped quotes and backslashes (Apache style)", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "Mozilla \\"quoted\\" a\\\\b"')
    t.eq(r.ua, 'Mozilla "quoted" a\\b')
  end)

  t.it("decodes nginx \\xNN escapes in every field", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET /?q=\\x22a\\x22 HTTP/1.1" 200 5 "http://x/\\x22" "caf\\xC3\\xA9\\x5Cn"')
    t.eq(r.target, '/?q="a"')
    t.eq(r.referer, 'http://x/"')
    t.eq(r.ua, "caf\u{e9}\\n")
  end)

  t.it("keeps unknown escapes and handles a trailing backslash", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "a\\d\\x4 b\\\\"')
    t.eq(r.ua, "a\\d\\x4 b\\")
  end)

  t.it("stops at an unescaped quote and ignores the rest of a sloppy user agent", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "Mozilla "evil" bot"')
    t.eq(r.ua, "Mozilla ")
  end)
end)

t.describe("combined parser: odd and hostile input", function()
  t.it("treats binary junk in the request line as an invalid request, not a bad line", function()
    local r = parsed(combined, '203.0.113.50 - - ' .. STAMP .. ' "\\x16\\x03\\x01\\x00\\xA5\\x01\\x00\\x00" 400 150 "-" "-"')
    t.is_true(r.invalid_request)
    t.is_nil(r.method)
    t.is_nil(r.path)
    t.eq(r.status, 400)
    local dash = parsed(combined, '203.0.113.51 - - ' .. STAMP .. ' "-" 408 0 "-" "-"')
    t.is_true(dash.invalid_request)
    local long_method = parsed(combined, '1.1.1.1 - - ' .. STAMP .. ' "' .. string.rep("A", 30) .. ' / HTTP/1.1" 400 0')
    t.is_true(long_method.invalid_request)
  end)

  t.it("rejects lines containing NUL bytes", function()
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "a\0b"', "binary")
    rejected(combined, string.rep("\0", 100), "binary")
  end)

  t.it("rejects lines missing core fields with a reason", function()
    rejected(combined, "", "timestamp")
    rejected(combined, "just some text", "timestamp")
    rejected(combined, "1.2.3.4", "timestamp")
    rejected(combined, '1.2.3.4 - - [10/Nov/2026:14:03:09 +0200', "unterminated [timestamp]")
    rejected(combined, '1.2.3.4 - - [not a date] "GET / HTTP/1.1" 200 5', "bad timestamp")
    rejected(combined, '1.2.3.4 - - [10/Foo/2026:14:03:09 +0200] "GET / HTTP/1.1" 200 5', "bad timestamp")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' GET / HTTP/1.1 200 5', "request")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1 200 5', "unterminated request")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 2x0 5', "status")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 99 5', "status")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 600 5', "status")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" - 5', "status")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 abc', "byte count")
    rejected(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 1234567890123456', "byte count")
    rejected(combined, '<script> - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5', "client address")
    rejected(combined, ' ' .. STAMP .. ' "GET / HTTP/1.1" 200 5', "client address")
  end)

  t.it("accepts truncated lines when the core fields are intact", function()
    local cut_in_agent = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "http://r/" "Mozilla/5.0 (Win')
    t.eq(cut_in_agent.referer, "http://r/")
    t.is_nil(cut_in_agent.ua)
    local cut_in_referer = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "http://r')
    t.is_nil(cut_in_referer.referer)
    local cut_after_status = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET /x HTTP/1.1" 200')
    t.eq({ cut_after_status.status, cut_after_status.bytes }, { 200, 0 })
    local cut_after_bytes = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET /x HTTP/1.1" 200 77 ')
    t.eq(cut_after_bytes.bytes, 77)
  end)

  t.it("bounds very long fields and lines", function()
    local huge_path = "/" .. string.rep("a", 500000)
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET ' .. huge_path .. ' HTTP/1.1" 200 5 "-" "' .. string.rep("u", 300000) .. '"')
    t.eq(#r.target, entry.MAX_TARGET)
    t.eq(#r.ua, entry.MAX_FIELD)
    local started = os.clock()
    rejected(combined, string.rep('"', 200000))
    rejected(combined, string.rep("\\", 200000) .. " [")
    rejected(combined, string.rep(" [", 100000))
    t.lt(os.clock() - started, 1)
  end)

  t.it("is not fooled by lookalike timestamps in later fields", function()
    local r = parsed(combined, '1.2.3.4 - - ' .. STAMP .. ' "GET /?x=%20[10/Oct/2000:13:55:36 HTTP/1.1" 200 5 "-" "-"')
    t.eq(r.ts, EPOCH)
  end)
end)

t.describe("combined parser: timings", function()
  local function with_tail(tail)
    return '1.2.3.4 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 5 "-" "UA"' .. tail
  end

  t.it("reads request_time and upstream_response_time", function()
    local r = parsed(combined, with_tail(" 0.250 0.248"))
    t.near(r.rt, 0.25, 1e-9)
    t.near(r.urt, 0.248, 1e-9)
    local only = parsed(combined, with_tail(" 2"))
    t.eq(only.rt, 2)
    t.is_nil(only.urt)
  end)

  t.it("sums multiple upstream times and ignores placeholders", function()
    local retried = parsed(combined, with_tail(" 0.300 0.100, 0.200"))
    t.near(retried.urt, 0.3, 1e-9)
    local dash = parsed(combined, with_tail(" 0.300 -"))
    t.is_nil(dash.urt)
    local redirect = parsed(combined, with_tail(" 0.300 0.100 : 0.050"))
    t.near(redirect.urt, 0.15, 1e-9)
  end)

  t.it("skips extra quoted fields such as X-Forwarded-For", function()
    local r = parsed(combined, with_tail(' "198.51.100.7, 10.0.0.1" 0.123'))
    t.near(r.rt, 0.123, 1e-9)
    local both = parsed(combined, with_tail(' 0.5 0.4 "extra"'))
    t.near(both.urt, 0.4, 1e-9)
  end)

  t.it("ignores non-numeric trailers and the whole tail in common mode", function()
    t.is_nil(parsed(combined, with_tail(" HIT")).rt)
    t.is_nil(parsed(combined, with_tail(" -1")).rt)
    local c = parsed(common, with_tail(" 0.5"))
    t.is_nil(c.rt)
    t.is_nil(c.ua)
    t.is_nil(c.extended)
  end)
end)

t.describe("json parser", function()
  local parse = parser.get("json")

  t.it("parses nginx escape=json lines (numbers as strings)", function()
    local r = parsed(parse, '{"time_iso8601":"2026-11-10T14:03:09+02:00","remote_addr":"203.0.113.9","request":"GET /a?b=1 HTTP/1.1","status":"200","body_bytes_sent":"512","http_referer":"-","http_user_agent":"curl/8","request_time":"0.123","upstream_response_time":"0.100, 0.020"}')
    t.eq(r.ip, "203.0.113.9")
    t.eq(r.ts, EPOCH)
    t.eq({ r.method, r.path, r.query, r.proto }, { "GET", "/a", "b=1", "HTTP/1.1" })
    t.eq({ r.status, r.bytes }, { 200, 512 })
    t.eq(r.ua, "curl/8")
    t.is_nil(r.referer)
    t.near(r.rt, 0.123, 1e-9)
    t.near(r.urt, 0.12, 1e-9)
  end)

  t.it("accepts camelCase and other key spellings", function()
    local r = parsed(parse, '{"timestamp":1794312189,"remoteAddr":"203.0.113.9:4000","requestMethod":"POST","requestUri":"/login","statusCode":401,"bytesSent":10,"userAgent":"x","Duration":0.5}')
    t.eq(r.ts, EPOCH)
    t.eq(r.ip, "203.0.113.9")
    t.eq({ r.method, r.path, r.status, r.bytes }, { "POST", "/login", 401, 10 })
    t.near(r.rt, 0.5, 1e-9)
  end)

  t.it("understands several timestamp shapes", function()
    local base = '"remote_addr":"1.1.1.1","method":"GET","uri":"/","status":200'
    for _, stamp in ipairs({ '"time":"10/Nov/2026:14:03:09 +0200"', '"time":"2026-11-10 12:03:09"',
      '"@timestamp":"2026-11-10T12:03:09.123Z"', '"ts":1794312189.9', '"ts":1794312189123',
      '"msec":"1794312189.123"' }) do
      t.eq(parsed(parse, "{" .. base .. "," .. stamp .. "}").ts, EPOCH, stamp)
    end
  end)

  t.it("prefers earlier aliases", function()
    local r = parsed(parse, '{"time":1,"time_iso8601":"2026-11-10T12:03:09Z","remote_addr":"1.1.1.1","method":"GET","status":200,"code":500,"uri":"/b","request_uri":"/a"}')
    t.eq({ r.ts, r.status, r.path }, { EPOCH, 200, "/a" })
  end)

  t.it("gives explicit reasons for bad lines", function()
    rejected(parse, "not json", "invalid JSON")
    rejected(parse, '{"a":', "invalid JSON")
    rejected(parse, "[1,2]", "not an object")
    rejected(parse, "null", "not an object")
    rejected(parse, "42", "not an object")
    rejected(parse, '{"remote_addr":"1.1.1.1","status":200}', "bad timestamp")
    rejected(parse, '{"remote_addr":"1.1.1.1","ts":1794312189}', "status")
    rejected(parse, '{"ts":1794312189,"status":200}', "client address")
    rejected(parse, '{"remote_addr":"<x>","ts":1794312189,"status":200}', "client address")
    rejected(parse, '{"remote_addr":"1.1.1.1","ts":1794312189,"status":2.5}', "status")
    rejected(parse, '{"remote_addr":"1.1.1.1","ts":1794312189,"status":"-"}', "status")
    rejected(parse, string.rep("[", 40) .. string.rep("]", 40), "invalid JSON")
  end)

  t.it("tolerates null fields, invalid UTF-8 and unrelated keys", function()
    local r = parsed(parse, '{"remote_addr":"1.1.1.1","ts":1794312189,"status":200,"user_agent":null,"referer":"x\xff","extra":{"a":[1,2]},"z":true}')
    t.is_nil(r.ua)
    t.eq(r.referer, "x\u{FFFD}")
  end)

  t.it("ignores absurdly long keys without caching them", function()
    local key = string.rep("k", 5000)
    local r = parsed(parse, '{"remote_addr":"1.1.1.1","ts":1794312189,"status":200,"' .. key .. '":1}')
    t.eq(r.status, 200)
  end)
end)

t.describe("caddy parser", function()
  local parse = parser.get("caddy")
  local LINE = '{"level":"info","ts":1794312189.5241024,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"198.51.100.9","remote_port":"41342","client_ip":"203.0.113.9","proto":"HTTP/2.0","method":"GET","host":"example.com","uri":"/a?b=1","headers":{"User-Agent":["curl/8.4.0"],"Referer":["https://example.com/"],"Accept":["*/*"]},"tls":{"resumed":false,"version":772}},"bytes_read":0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"]}}'

  t.it("parses a default Caddy access record", function()
    local r = parsed(parse, LINE)
    t.eq(r.ip, "203.0.113.9")
    t.eq(r.ts, EPOCH)
    t.eq({ r.method, r.path, r.query, r.proto }, { "GET", "/a", "b=1", "HTTP/2.0" })
    t.eq({ r.status, r.bytes }, { 200, 10900 })
    t.eq(r.ua, "curl/8.4.0")
    t.eq(r.referer, "https://example.com/")
    t.near(r.rt, 0.000929675, 1e-12)
  end)

  t.it("falls back to remote_ip / remote_addr and handles ports and IPv6", function()
    local a = parsed(parse, '{"ts":1794312189,"request":{"remote_ip":"198.51.100.9","method":"GET","uri":"/"},"status":200}')
    t.eq(a.ip, "198.51.100.9")
    local b = parsed(parse, '{"ts":1794312189,"request":{"remote_addr":"198.51.100.9:4433","method":"GET","uri":"/"},"status":200}')
    t.eq(b.ip, "198.51.100.9")
    local c = parsed(parse, '{"ts":1794312189,"request":{"remote_addr":"[2001:db8::1]:4433","method":"GET","uri":"/"},"status":200}')
    t.eq(c.ip, "2001:db8::1")
  end)

  t.it("reads headers case-insensitively and takes the first value", function()
    local r = parsed(parse, '{"ts":1794312189,"request":{"client_ip":"1.1.1.1","method":"GET","uri":"/","headers":{"user-agent":["a","b"],"REFERER":["https://r/"]}},"status":200}')
    t.eq({ r.ua, r.referer }, { "a", "https://r/" })
  end)

  t.it("accepts ISO timestamps from a custom time_format", function()
    local r = parsed(parse, '{"ts":"2026-11-10T12:03:09.000Z","request":{"client_ip":"1.1.1.1","method":"GET","uri":"/"},"status":404}')
    t.eq(r.ts, EPOCH)
  end)

  t.it("rejects error-log lines and malformed records", function()
    rejected(parse, '{"level":"error","ts":1794312189,"logger":"tls","msg":"cert expired"}', "not a Caddy access record")
    rejected(parse, '{"level":"error","ts":1794312189,"request":{"client_ip":"1.1.1.1"},"msg":"x"}', "not a Caddy access record")
    rejected(parse, '{"ts":1794312189,"request":null,"status":200}', "not a Caddy access record")
    rejected(parse, "[]", "not a Caddy access record")
    rejected(parse, "garbage", "invalid JSON")
    rejected(parse, '{"request":{"client_ip":"1.1.1.1"},"status":200}', "bad timestamp")
    rejected(parse, '{"ts":1794312189,"request":{"client_ip":"1.1.1.1"},"status":200.5}', "status")
    rejected(parse, '{"ts":1794312189,"request":{},"status":200}', "client address")
  end)
end)

t.describe("parser registry and auto-detection", function()
  local NGINX = '203.0.113.9 - - ' .. STAMP .. ' "GET / HTTP/1.1" 200 512 "https://e/" "Mozilla/5.0"'
  local COMMON = '203.0.113.9 - bob ' .. STAMP .. ' "GET / HTTP/1.0" 200 512'
  local JSON_LINE = '{"remote_addr":"203.0.113.9","ts":1794312189,"request_uri":"/","status":200}'
  local CADDY = '{"ts":1794312189.5,"request":{"client_ip":"203.0.113.9","method":"GET","uri":"/"},"status":200,"size":1,"duration":0.1}'

  t.it("lists formats with documentation", function()
    t.eq(parser.names(), { "combined", "common", "json", "caddy" })
    for _, format in ipairs(parser.FORMATS) do
      t.ok(format.description and format.example, format.name)
      local parse = parser.get(format.name)
      t.ok(parse(format.example), "the documented example for " .. format.name .. " must parse")
    end
  end)

  t.it("rejects unknown format names", function()
    local parse, err = parser.get("apache2")
    t.is_nil(parse)
    t.contains(err, "unknown format 'apache2'")
  end)

  t.it("detects each format", function()
    t.eq((parser.detect({ NGINX, NGINX })), "combined")
    t.eq((parser.detect({ COMMON, COMMON })), "common")
    t.eq((parser.detect({ JSON_LINE })), "json")
    t.eq((parser.detect({ CADDY, CADDY })), "caddy")
  end)

  t.it("ignores blank lines and tolerates junk among the samples", function()
    local name, info = parser.detect({ "", "   ", "# header comment", NGINX, "garbage", NGINX, "" })
    t.eq(name, "combined")
    t.eq(info, { sampled = 4, matched = 2 })
    t.eq((parser.detect({ "", "", CADDY })), "caddy")
  end)

  t.it("returns nil for empty or unparseable samples", function()
    t.is_nil((parser.detect({})))
    t.is_nil((parser.detect({ "", "  " })))
    local name, info = parser.detect({ "hello world", "{not json}", "42" })
    t.is_nil(name)
    t.eq(info.matched, 0)
  end)

  t.it("prefers combined when any sampled line has extended fields", function()
    t.eq((parser.detect({ COMMON, NGINX, COMMON })), "combined")
  end)

  t.it("prefers the majority family in mixed samples", function()
    t.eq((parser.detect({ JSON_LINE, JSON_LINE, NGINX })), "json")
    t.eq((parser.detect({ NGINX, NGINX, JSON_LINE })), "combined")
  end)
end)

t.describe("parser robustness (fuzz)", function()
  local SEEDS = {
    '203.0.113.9 - - ' .. STAMP .. ' "GET /a/b?c=1 HTTP/1.1" 200 512 "https://e/" "Mozilla/5.0 (X11)" 0.1 0.05',
    '::1 - bob [10/Oct/2000:13:55:36 -0700] "POST /x HTTP/1.0" 404 - "-" "-"',
    '{"remote_addr":"1.1.1.1","time_iso8601":"2026-11-10T12:03:09Z","request":"GET /x HTTP/1.1","status":200,"request_time":"0.1"}',
    '{"ts":1794312189.5,"request":{"client_ip":"1.1.1.1","method":"GET","uri":"/","headers":{"User-Agent":["x"]}},"status":200,"size":1,"duration":0.1}',
  }

  local function mutate(rng, text)
    local chars = {}
    for i = 1, #text do
      chars[i] = text:sub(i, i)
    end
    for _ = 1, rng:range(1, 6) do
      if #chars == 0 then
        break
      end
      local at = rng:range(1, #chars)
      local op = rng:range(1, 5)
      if op == 1 then
        table.remove(chars, at)
      elseif op == 2 then
        chars[at] = string.char(rng:range(0, 255))
      elseif op == 3 then
        table.insert(chars, at, rng:pick({ '"', "\\", "[", "]", " ", "-", "{", "}", ":", "\0", "%" }))
      elseif op == 4 then
        for i = #chars, at + 1, -1 do
          chars[i] = nil
        end
      else
        table.insert(chars, at, chars[rng:range(1, #chars)])
      end
    end
    return table.concat(chars)
  end

  t.it("never raises and only returns well-formed records", function()
    local rng = lcg.new(1337)
    local parses = { combined, common, parser.get("json"), parser.get("caddy") }
    for _ = 1, 4000 do
      local line = mutate(rng, rng:pick(SEEDS))
      for _, parse in ipairs(parses) do
        local ok, record, reason = pcall(parse, line)
        t.ok(ok, "parser must not raise on " .. t.inspect(line) .. ": " .. tostring(record))
        if record then
          t.eq(math.type(record.ts), "integer")
          t.ok(record.status >= 100 and record.status <= 599)
          t.ok(record.bytes >= 0)
          t.ok(entry.valid_address(record.ip))
          t.ok(record.path == nil or #record.path <= entry.MAX_TARGET)
          t.is_nil(record.ip:find("[^%w%.:_%-%%%[%]]"))
        else
          t.eq(type(reason), "string")
        end
      end
    end
  end)

  t.it("survives completely random bytes", function()
    local rng = lcg.new(4242)
    local parses = { combined, common, parser.get("json"), parser.get("caddy") }
    for _ = 1, 1000 do
      local bytes = {}
      for i = 1, rng:range(0, 300) do
        bytes[i] = string.char(rng:range(0, 255))
      end
      local line = table.concat(bytes)
      for _, parse in ipairs(parses) do
        t.ok(pcall(parse, line))
      end
      t.ok(pcall(parser.detect, { line }))
    end
  end)
end)
