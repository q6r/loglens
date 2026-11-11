# Command-line reference

```
loglens [report] [options] <file|->...    dashboard for a finished log (the default command)
loglens json     [options] <file|->...    machine-readable summary (schema loglens.summary/v1)
loglens html     [options] <file|->...    self-contained HTML report (works offline)
loglens watch    [options] <file|->       follow a growing log and redraw the dashboard live
loglens formats                           list the supported log formats
loglens version                           print the version
```

`-` reads standard input. Several files are analysed together, in the order given. Options may come
before or after the file names; `--` ends the options. `loglens <command> --help` prints the options
of one command. Run from a checkout as `lua bin/loglens ...` (`bin\loglens.cmd` on Windows).

## Options

| Option | Commands | Meaning |
|---|---|---|
| `-f, --format NAME` | all analysing commands | `auto` (default), `combined`, `common`, `json` or `caddy`; see [formats.md](formats.md) |
| `--from TIME`, `--to TIME` | all analysing commands | Only requests inside the window count. ISO 8601 (`2026-11-10`, `2026-11-10T14:00`, `2026-11-10 14:00:30+02:00`) or epoch seconds. A plain date given to `--to` covers the whole day. Times without a zone are UTC. |
| `-n, --top N` | all analysing commands | Rows per ranked list, 1 to 100 (default 10). |
| `--color WHEN`, `--no-color` | report, watch | `auto` (default), `always` or `never`. |
| `--ascii` | report, watch | Draw with plain ASCII (`#` bars, `.:-=+*#@` sparklines) instead of block characters. |
| `--width COLS` | report, watch | Dashboard width, 40 to 240. Default: the terminal width on a terminal, otherwise 100. |
| `-o, --output FILE` | json, html | Write to a file instead of standard output. The input file is never overwritten. |
| `--compact` | json | One line instead of pretty-printed JSON. |
| `--fail-on SEVERITY` | report, json, html | Exit with status 3 when a finding of at least this severity exists (`info`, `low`, `medium`, `high`, `critical`). |
| `--interval SECONDS` | watch | Seconds between redraws, 0.05 to 60 (default 0.25). |
| `--frames N` | watch | Stop after N frames. Default: run until the input ends or Ctrl+C. |
| `--new-only` | watch | Skip what the file already holds and show only new requests. |

## Exit status

| Status | Meaning |
|---|---|
| 0 | success |
| 1 | failure: unreadable input, an output file that cannot be written, or **no line could be parsed** (usually a wrong `--format`; the report still explains it) |
| 2 | usage error: unknown option, invalid value, no input |
| 3 | `--fail-on`: at least one finding reached the severity (the report is still written) |
| 130 | interrupted (Ctrl+C in watch mode) |

An empty log is not an error: it prints "No requests parsed." and exits 0.

## Environment

| Variable | Effect |
|---|---|
| `NO_COLOR` | any non-empty value turns colour off (`--color always` still wins) |
| `FORCE_COLOR` | any value except `0` turns colour on |
| `TERM=dumb` | turns colour off |
| `COLUMNS`, `LINES` | the terminal size, when the shell exports them |
| `SOURCE_DATE_EPOCH` | the time stored in `meta.generatedAt`, for reproducible output |
| `LOGLENS_DEBUG` | a stack trace with unexpected errors |

## Colour and width: what is detected

Plain Lua cannot ask a terminal about itself, so `platform.lua` asks the system:

* **Is output a terminal?** POSIX: `[ -t 1 ]` through the shell. Windows: terminals that announce
  themselves (`WT_SESSION`, `ANSICON`, `ConEmuANSI`, `TERM`, `TERM_PROGRAM`); redirecting output does
  not change this, so pass `--no-color` when saving a report from a Windows terminal.
* **Terminal size:** `COLUMNS` and `LINES`, then `stty size` (POSIX) or `mode con` (Windows).
* Colour is used when output is a terminal, `NO_COLOR` is not set and `TERM` is not `dumb`.
  A redirected `report` is plain text without escape sequences.
* The dashboard uses Unicode block and box characters. On a Windows console that is not UTF-8
  (cmd.exe with an OEM code page) run `chcp 65001` first or pass `--ascii`; Windows Terminal needs
  neither.

## Examples

```console
$ lua bin/loglens report examples/access.log --top 5 --no-color --width 100
 loglens  examples/access.log · combined · 2026-11-09 06:08 → 2026-11-16 05:49 UTC (7d)

 REQUESTS        BANDWIDTH       VISITORS        AVG RATE        5XX RATE        LATENCY P99
 3,422           113.9 MiB       210             0.01/s          3.1%            2.3 s
 peak 207/min    avg 34.1 KiB    unique IPs      over 7d         4xx 3.7%        p50 18 ms
 ...
```

```console
$ SOURCE_DATE_EPOCH=1794830400 lua bin/loglens json examples/access.log --compact | head -c 200
{"schema":"loglens.summary/v1","meta":{"tool":"loglens","version":"0.1.0","generatedAt":"2026-11-16T12:00:00Z","sources":["examples/access.log"],"format":"combined","autoDetected":true,"lines":{"total
```

```console
$ lua bin/loglens html examples/access.log -o report.html
loglens: wrote report.html (253.3 KiB)
```

**A gate for CI or cron.** Findings of severity high or above fail the job, the report is still printed:

```console
$ lua bin/loglens json examples/access.log --compact --fail-on high > summary.json
loglens: 5 findings at or above 'high'
$ echo $?
3
```

**Rotated and compressed logs.** `zcat` feeds loglens through standard input:

```console
$ zcat access.log.2.gz access.log.1.gz | lua bin/loglens report - access.log
```

**A time window.** One day of a log, in UTC:

```console
$ lua bin/loglens json access.log --from 2026-11-15 --to 2026-11-15 -o day.json
```

**Mistakes are explained.**

```console
$ lua bin/loglens report nope.log
loglens: nope.log: No such file or directory
$ lua bin/loglens report examples/access.log --formt json
loglens: unknown option '--formt'. Did you mean '--format'? (see 'loglens report --help')
$ lua bin/loglens jsn examples/access.log
loglens: unknown command 'jsn'. Did you mean 'json'?
```

## Watch mode

`loglens watch /var/log/nginx/access.log` reads what the file already holds (so the dashboard is not
empty), then follows it and redraws at a steady rate. The header shows an animated LIVE marker, a
spinner and how many lines arrived during the last second. Ctrl+C restores the terminal.

* **Rotation** is detected by polling the path: a file that shrank, whose first bytes changed or
  that disappeared and came back is read from its start, and the header says
  "log rotated, following the new file" for a couple of seconds. Lines written to the old file
  after a rename-style rotation are not seen.
* **Backlog:** a big file is read in slices between redraws, so the numbers climb on screen
  instead of the dashboard freezing.
* **Terminal height:** when the dashboard is taller than the terminal, the least important lists
  are left out (see [architecture.md](architecture.md)); resizing is picked up within about two
  seconds.
* **Output that is not a terminal** (a pipe or a file) gets plain frames one after another instead
  of cursor control, and `--frames N` makes that useful in scripts.
* **Standard input** (`tail -f access.log | loglens watch -`) redraws whenever lines arrive. Plain
  Lua cannot poll a pipe without blocking, so the spinner does not move while the pipe is idle; when
  the stream ends, the last frame stays as a normal report.
* Sleeping uses LuaSocket's `socket.sleep` when it is installed, the `sleep` command on POSIX, and a
  short busy-wait on Windows without LuaSocket (it keeps one core busy; install LuaSocket to avoid
  that).
