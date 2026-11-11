# Supported log formats

`loglens formats` prints the same list. With `--format auto` (the default) the format is decided
from the first ten non-blank lines: every line votes for the formats that can parse it, text lines
vote for `combined` when they carry referer and user-agent fields and for `common` otherwise, and
JSON objects vote for `caddy` when they look like Caddy access records and for `json` otherwise.
The majority wins. `meta.autoDetected` in the summary tells which way the format was chosen.
Force a format with `--format` when a log is odd, for example when it starts with a banner.

Malformed lines never stop the run: they are counted, and the first five are kept (cut to 160
bytes, control characters escaped) as `meta.malformedSamples`. A log in which every line is
rejected makes the command exit with status 1 after showing why.

## combined (nginx, Apache)

```
203.0.113.9 - alice [10/Nov/2026:14:03:09 +0200] "GET /a?b=1 HTTP/1.1" 200 512 "https://example.com/" "Mozilla/5.0" 0.123 0.100
```

The default `combined` format of both servers. Two optional extras are understood:

* trailing numbers are read as `request_time` and `upstream_response_time` in seconds. With nginx:
  `log_format timed '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time';`
* extra quoted fields after the user agent (such as `X-Forwarded-For`) are ignored.

The tokenizer is hand written and tolerates what real logs contain: IPv6 addresses, `-` placeholders,
user names with spaces, escaped quotes (`\"`, `\\`, nginx `\x22`), unencoded spaces inside the
request target, binary garbage in the request line, `ip:port` clients, Apache `vhost:port` prefixes
and truncated lines. A line is rejected only when the client, timestamp, request line or status is
unusable.

## common (Common Log Format)

```
203.0.113.9 - frank [10/Nov/2026:14:03:09 +0000] "GET /a HTTP/1.0" 200 2326
```

No referer and no user agent, so referrer lists are empty and every request counts as an unknown
agent. Anything after the byte count is ignored.

## json (JSON lines)

One JSON object per line, as written by nginx with `escape=json`, Traefik-style and home-grown
loggers. Keys are compared case-insensitively with punctuation removed (`remote_addr`, `remoteAddr`
and `RemoteAddr` are one key); within a field, earlier names win.

| Field | Accepted keys |
|---|---|
| client | `remote_addr`, `remote_ip`, `client_ip`, `client_addr`, `ip`, `remote_host` |
| time | `time_iso8601`, `time_local`, `msec`, `time`, `timestamp`, `@timestamp`, `ts`, `datetime`, `date` |
| request line | `request`, `request_line` |
| method | `request_method`, `method`, `http_method`, `verb` |
| target | `request_uri`, `uri`, `url`, `request_url`, `path`, `request_path`, `url_path` |
| protocol | `server_protocol`, `protocol`, `proto`, `http_version` |
| status | `status`, `status_code`, `response_status`, `http_status`, `code` |
| bytes | `body_bytes_sent`, `bytes_sent`, `bytes`, `size`, `response_size`, `response_bytes` |
| referer | `referer`, `referrer`, `http_referer`, `http_referrer` |
| user agent | `user_agent`, `http_user_agent`, `ua`, `agent` |
| request time | `request_time`, `response_time`, `duration`, `latency`, `elapsed`, `rt` (seconds) |
| upstream time | `upstream_response_time`, `upstream_time`, `urt` (seconds) |

Numbers may be JSON numbers or numeric strings. Times may be epoch seconds, milliseconds,
microseconds or nanoseconds (the unit is guessed from the magnitude), ISO 8601 or Common Log Format.

## caddy (Caddy v2 access logs)

```json
{"level":"info","ts":1762783389.5,"logger":"http.log.access.log0","msg":"handled request",
 "request":{"remote_ip":"203.0.113.9","client_ip":"203.0.113.9","proto":"HTTP/2.0","method":"GET",
 "host":"example.com","uri":"/a?b=1","headers":{"User-Agent":["curl/8"]}},
 "duration":0.0009,"size":10900,"status":200}
```

The client is `request.client_ip` (falling back to `remote_ip` and `remote_addr`), the time is `ts`,
the latency is `duration` (seconds) and the size is `size`. Header names are matched
case-insensitively. Records without `request` and a numeric `status` (error-log lines that share the
file) are rejected as "not a Caddy access record".

## Limits applied to every format

| Limit | Value | Effect |
|---|---|---|
| line length | 65,536 bytes | longer lines are rejected as malformed and never held in memory |
| request target | 2,048 bytes | longer targets are cut |
| referer, user agent | 1,024 bytes | longer values are cut |
| client address | 255 bytes, `A-Z a-z 0-9 . : _ - % [ ]` only | anything else rejects the line |

Not supported: compressed logs (pipe them through `zcat access.log.1.gz | loglens report -`),
multi-line records, and syslog envelopes around the access line.
