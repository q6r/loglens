# JSON output: the `loglens.summary/v1` schema

`loglens json` prints it, `loglens html` embeds it, the terminal dashboard is drawn from it and
`loglens.summary.validate` checks it. It is plain data (nested tables, arrays and scalars), encoded
deterministically: fixed key order, every list sorted with explicit tie-breakers, so the same log
always gives the same bytes. Only `meta.generatedAt` varies; set `SOURCE_DATE_EPOCH` to fix it.

Conventions: times are UTC ISO 8601 strings (`2026-11-10T14:03:09Z`), ratios are fractions between 0
and 1 (`0.0374` is 3.74 %), sizes are bytes, durations are milliseconds, and "ranked" lists are
sorted by `count`, descending. Optional keys are omitted, never `null`.

```json
{
  "schema": "loglens.summary/v1",
  "meta":      { "tool": "loglens", "version": "0.1.0", "generatedAt": "2026-11-16T12:00:00Z",
                 "sources": ["examples/access.log"], "format": "combined", "autoDetected": true,
                 "lines": { "total": 3422, "parsed": 3422, "malformed": 0, "blank": 0, "outsideWindow": 0 },
                 "window": {}, "limits": { "...": "..." }, "malformedSamples": [] },
  "totals":    { "requests": 3422, "bytes": 119470642, "uniqueIps": 210, "uniqueIpsExact": true, "...": "..." },
  "status":    { "classes": [ "..." ], "codes": [ "..." ] },
  "methods":   [ "..." ], "paths": [ "..." ], "clients": [ "..." ], "referrers": [ "..." ],
  "agents":    { "classes": [ "..." ], "families": [ "..." ], "top": [ "..." ] },
  "errorPaths": { "notFound": [ "..." ], "serverErrors": [ "..." ] },
  "timeline":  { "minute": { "...": "..." }, "hour": { "...": "..." } },
  "latency":   { "...": "(only when the log has request times)" },
  "errorSpikes": [ "..." ],
  "findings":  [ "..." ]
}
```

## meta

| Key | Type | Meaning |
|---|---|---|
| `tool`, `version` | string | `loglens` and its version |
| `generatedAt` | string, optional | when the summary was built (`SOURCE_DATE_EPOCH` or the clock) |
| `sources` | string[] | the inputs as given; `-` is reported as `stdin` |
| `format` | string | `combined`, `common`, `json` or `caddy` |
| `autoDetected` | boolean | whether the format was detected or forced with `--format` |
| `lines` | object | `total` lines read, `parsed` records, `malformed`, `blank`, and `outsideWindow` (parsed but outside `--from`/`--to`) |
| `window` | object | `from` and `to` when a time window was requested (otherwise `{}`) |
| `limits` | object | the bounds the sketches ran with: `topCapacity`, `uniqueExactLimit`, `maxLineBytes`, `minuteBuckets`, `hourBuckets` |
| `malformedSamples` | object[] | up to five `{ line, reason, preview }`; `preview` is escaped and cut to 160 bytes |

## totals

| Key | Type | Meaning |
|---|---|---|
| `requests`, `bytes` | integer | requests inside the window and their total response bytes |
| `uniqueIps` | integer | distinct client addresses; exact up to 10,000, then a HyperLogLog estimate (about 1.6 % error) |
| `uniqueIpsExact` | boolean | `false` when `uniqueIps` is an estimate |
| `firstSeen`, `lastSeen` | string | first and last request time (omitted when there are no requests) |
| `spanSeconds`, `avgRps` | number | covered time and requests per second over it |
| `peakMinute` | object | `{ start, requests, rps }` of the busiest minute |
| `clientErrorRate`, `serverErrorRate` | number | share of 4xx and of 5xx responses |
| `invalidRequests` | integer | requests whose request line could not be understood |

## status, methods

* `status.classes`: five entries `1xx` to `5xx`: `{ class, count, share }`.
* `status.codes`: the most frequent codes: `{ code, count }`.
* `methods`: `{ method, count, share }`; unusual names are folded into `(other)`, unparsable ones into `(invalid)`.

## Ranked lists

`paths`, `clients`, `referrers`, `agents.top`, `errorPaths.notFound` and `errorPaths.serverErrors`
share one shape: the key (`path`, `ip`, `host` or `agent`), `count` and `overcount`. The lists come
from Space-Saving sketches, so on logs with more distinct keys than the capacity a count can be too
high by at most `overcount`; it is `0` when nothing was ever evicted. Extra fields:

| List | Extra fields |
|---|---|
| `paths` | `bytes`, `errors` (4xx and 5xx responses) |
| `clients` | `bytes`, `errors`, `peakPerMinute` |
| `agents.top` | `class`, `family` |

Paths are the request path without query string (cut at 200 bytes), referrers are reduced to the host.

## agents

* `classes`: `{ class, count, share }` for `human`, `bot`, `tool`, `scanner`, `unknown`.
* `families`: `{ name, class, count, share }`, for example `Chrome`, `Googlebot`, `sqlmap`.
* `top`: the raw user-agent strings (see ranked lists).

## timeline

`minute` and `hour` have the same shape: `{ step, start, requests[], s2xx[], s3xx[], s4xx[], s5xx[], bytes[] }`.
`start` is the epoch second of the first bucket and `step` the bucket length (60 or 3600); all arrays have
the same length. The summary keeps the most recent 1,440 minutes and 720 hours of the log. Empty buckets
between requests are present as zeros.

## latency

Present only when the log has request times (`$request_time`, Caddy `duration`, JSON `request_time`).

`{ unit: "ms", count, mean, p50, p90, p95, p99, max, upstream?, slowest[] }`.
Percentiles come from a logarithmic histogram with 1 % relative accuracy. `upstream` has the same
fields for `upstream_response_time` when the log has it. `slowest` lists up to `--top` paths with
at least five timed requests: `{ path, count, avgMs, maxMs }`, slowest average first.

## errorSpikes

Windows of consecutive minutes whose 5xx count is a robust outlier (modified z-score of at least
3.5, at least five errors, at least ten minutes of data):
`{ from, to, minutes, serverErrors, requests, rate, peak, peakAt, score }`.

## findings

`{ id, title, severity, count, evidence[], limitations[], ips[] }`, most severe first. `severity` is
`info`, `low`, `medium`, `high` or `critical`. See [security-heuristics.md](security-heuristics.md)
for every id.

## Validation and compatibility

`loglens.summary.validate(summary)` returns `true`, or `false` and a list of messages that start with the
path of the offending field (`$.totals.requests: expected an integer >= 0`). New fields may be added
within `v1`; a field is never removed or changed in meaning without a new schema id, so readers
should ignore keys they do not know.
