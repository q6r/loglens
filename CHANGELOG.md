# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The HTML report moved to Aurora 2.0, the bundled UI kit, and is laid out like an app in the kit's
  near-black Prism Classic palette (and its light variant): a navigation rail with one destination per
  section that follows the scroll, breadcrumbs, a Charts / Tables switch for every chart, context pills
  (period, requests, bytes sent, format) and a status bar. The page itself is now built by
  `report.js`; the HTML document holds only the no-script fallback, the data and the scripts.
- Screenshots, the terminal stills, the animated terminal recording (`tools/make_recording.lua`, now in the
  same near-black palette and static under reduced motion) and the README banner were regenerated for the
  new look.

## [0.1.0] - 2026-11-10

First release.

### Added

- Log parsers for nginx and Apache **combined** and **common** logs, **JSON lines** and **Caddy v2**
  access logs, with automatic format detection and tolerance for the things real logs contain (IPv6,
  escaped quotes, unencoded spaces, truncated lines, binary garbage).
- Streaming analyzer with **bounded memory**: Space-Saving sketches for top paths, clients,
  referrers, user agents, 404 and 5xx paths; exact-then-HyperLogLog unique visitors; minute and
  hour timelines; a logarithmic latency histogram (p50, p90, p95, p99, max) with upstream times.
- **Security heuristics** with evidence and stated limitations: path probing, path traversal,
  SQL injection, XSS, command injection, Log4Shell, scanner user agents, brute force and request
  rate outliers.
- Terminal dashboard with sparklines, bars, status mix, findings, an ASCII mode and colour control.
- `loglens report`, `json`, `html`, `watch`, `formats` and `version` commands; stdin as `-`; time
  window (`--from`, `--to`); `--top`; `--fail-on` exit status for CI gates.
- **Watch mode**: follows a growing file or standard input, redraws an animated dashboard at a
  steady rate, detects log rotation, fits the terminal height and restores the terminal on exit.
- Self-contained **HTML report** built with the bundled Aurora UI kit: key figures, requests over time,
  status classes, weekday-by-hour heatmap, ranked lists, response times, user-agent classes,
  findings with evidence, dark and light themes, command palette. No network requests; inline
  scripts and styles are pinned by SHA-256 in a Content-Security-Policy.
- Summary schema `loglens.summary/v1` with a validator and deterministic JSON encoding.
- Synthetic log generator (`tools/loggen.lua`), generated `examples/` and an animated SVG
  recording of the live dashboard built from real frames (`tools/make_recording.lua`).
- Rockspec, luacheck and stylua configuration, GitHub Actions workflow.

### Security

- Everything that comes from a log is escaped before it reaches the terminal (control characters,
  invalid UTF-8, bidirectional and invisible code points, markup and shell syntax) and the HTML
  report embeds its data as an escaped JSON island and draws every string with `textContent`.
- Lines longer than 64 KiB are discarded while they are being read, never held in memory (the exception is `watch -`, which reads standard input line by line).

[Unreleased]: https://github.com/q6r/loglens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/q6r/loglens/releases/tag/v0.1.0
