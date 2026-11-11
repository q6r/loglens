# Security heuristics

Everything here is a heuristic over what an access log contains: method, URL, status, user agent,
referer and timing. It finds **attempts and suspicious patterns, not compromises**. An access log
shows requests, not their effect, and does not contain request bodies or most headers.

Every finding carries `evidence` (what matched, from which addresses, when, with sample requests)
and `limitations` (what the heuristic cannot see and when it is wrong). Both are in the JSON
summary and in the HTML report (select a finding); the terminal dashboard lists the findings and
points to `--json`. Evidence text that came from a log is escaped: control characters, invalid
UTF-8 and invisible or bidirectional code points are written as `\xNN` or `\uXXXX`, and `< > " ' ` $ { } \`
are percent-encoded, so a hostile request cannot inject markup, terminal sequences or shell syntax
into a report.

Findings are sorted by severity (critical, high, medium, low, info), then by id.
`--fail-on SEVERITY` makes the command exit with status 3 when at least one finding reaches that
severity, which is how to use loglens as a gate in CI or a cron job.

## What is detected

| Id | Title | Severity | Trigger |
|---|---|---|---|
| `path-probing` | Probing for sensitive or admin paths | low, medium or high | A client requests a **sensitive** path once (`.env`, `.git/`, `.aws/credentials`, `id_rsa`, `wp-config.php`, backup archives and SQL dumps, web shells, `/vendor/phpunit/`, `/actuator/env` ...), or trips **three or more different rules** (WordPress login, phpMyAdmin and Adminer, `cgi-bin` and IoT router paths, `/actuator`, `server-status`, `phpinfo.php`, Tomcat manager). CONNECT and absolute-URI requests count as `open-proxy` probes. |
| `path-traversal` | Path traversal or local file inclusion attempts | medium, high | `../` segments, system files (`/etc/passwd`, `win.ini` ...), stream wrappers (`php://`, `file://` ...) and null bytes in the decoded URL. |
| `sql-injection` | SQL injection signatures in URLs | medium, high | `UNION SELECT`, tautologies (`OR 1=1`), time-based payloads (`sleep(`, `waitfor delay`), schema and file functions (`information_schema`, `load_file(`), stacked `; drop`, quote plus comment. |
| `xss` | Cross-site scripting signatures in URLs | low, medium | `<script>` and other HTML tags, `onerror=` style event handlers, `javascript:` URIs. |
| `command-injection` | Command or code injection signatures | high | Shell paths and `$(...)`, `wget`/`curl` downloads, PHP code (`<?php`, `eval(`), Spring class-loader properties (`class.module.classloader`) in the URL; Shellshock `() {` in the URL, user agent or referer. |
| `log4shell` | Log4Shell (JNDI lookup) attempts | high | `${jndi:ldap://...}` and the common obfuscations (`${${lower:j}ndi:...}`) in the URL, user agent or referer. |
| `scanner-agents` | Security scanners identified by user agent | medium | User agents of known tools and research scanners (sqlmap, Nikto, ZGrab, Nmap and similar). |
| `brute-force` | Possible brute-force or credential stuffing | medium, high | One address makes **10 or more** authentication attempts (401 or 403 responses, or POSTs to login-like URLs) inside one aligned 5-minute window. |
| `rate-outlier` | Clients with outlier request rates | low | A client's busiest minute has at least 60 requests **and** is a robust outlier (modified z-score of at least 3.5) among the tracked clients' busiest minutes; needs 8 clients and 100 requests. |

### Severity rules

* `path-probing`: low; medium from 25 probe requests or 5 distinct rules; **high** when a sensitive
  file probe was answered with a 2xx status.
* `path-traversal`: medium; **high** when a request was answered with a 2xx status.
* `sql-injection`: medium; **high** from 25 matching requests.
* `xss`: low; medium from 10 matching requests.
* `command-injection` and `log4shell`: high.
* `scanner-agents`: medium.
* `brute-force`: medium; **high** when one window reached 50 attempts or the total reached 100.
* `rate-outlier`: low.

A 2xx answer to an attack does not prove it worked (single-page apps answer every path with 200),
which is why the evidence says "answered with a 2xx status" and not "succeeded".

## How requests are inspected

The request target (path and query, first 2 KiB) is lower-cased, percent-decoded **twice** (to see
double encoding), `+` becomes a space, SQL comments (`/**/`) become spaces and white space is
collapsed, and only then compared with the signatures. User agent and referer are scanned only for
the signatures that matter there (Log4Shell and Shellshock). Matching uses plain string and pattern
tests; nothing from a log is ever executed or evaluated.

## Limitations (all findings)

* Only what the access log records is visible: no POST bodies, cookies or most headers. Payloads in
  those places are invisible.
* Matches are **attempts**. Legitimate traffic can match: a search box for SQL words, a coding
  tutorial site, a site that really serves WordPress admin pages, a vulnerability scanner you run
  yourself.
* User agents are self-reported: scanners that pose as browsers are missed; research scanners are
  noisy but not necessarily hostile.
* Clients behind NAT, a proxy or a CDN are merged into one address unless the log records the real
  client address (use `$http_x_forwarded_for` or Caddy's `client_ip`).
* Per-client state lives in bounded-memory sketches (512 clients per heuristic): on very busy logs,
  low-volume scanners can be evicted. Per-minute peaks assume mostly chronological logs.
* Slow and distributed attacks (one attempt per address) are not detected by the brute-force
  heuristic, and the rate heuristic only compares tracked clients with each other.

Each finding states its own limitations in more detail; the strings are part of the summary so a
report is self-explanatory when it is shared.

## Thresholds

The defaults live in `loglens.security.DEFAULTS` and can be changed when using the library:

| Setting | Default | Meaning |
|---|---|---|
| `capacity` | 512 | clients tracked per heuristic |
| `probe_min_rules` | 3 | different non-sensitive rules before a client counts as a prober |
| `burst_window` | 300 | seconds in one authentication window |
| `burst_min_attempts` | 10 | attempts in a window before an address is reported |
| `burst_high_attempts` | 50 | attempts in a window for severity high |
| `rate_min_peak` | 60 | requests in a minute before a client can be an outlier |
| `rate_min_clients` / `rate_min_requests` | 8 / 100 | data needed before comparing rates |
| `rate_z` | 3.5 | modified z-score threshold |
| `max_ips`, `evidence_ips`, `evidence_width` | 10, 5, 110 | how much evidence is kept |

```lua
local analyzer = require("loglens.analyzer").new({ security = { burst_min_attempts = 5 } })
```
