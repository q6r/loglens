# Contributing

Thanks for helping. loglens is plain Lua with no dependencies, so setting up takes a minute.

## Setup

You need Lua 5.3 or 5.4. LuaJIT is not supported (the code uses integers, bit operators and `utf8`).

```console
git clone https://github.com/q6r/loglens
cd loglens
lua spec/run.lua            # the whole suite, a few seconds
lua spec/run.lua -v         # one line per test
lua bin/loglens report examples/access.log
```

Optional tools: [luacheck](https://github.com/lunarmodules/luacheck) (`luarocks install luacheck`)
and [stylua](https://github.com/JohnnyMorganz/StyLua).

```console
make test                   # lua spec/run.lua
make lint                   # luacheck src spec tools bin/loglens
make format                 # stylua .   (make check-format only verifies)
make examples               # regenerate examples/ (deterministic)
make recording              # regenerate docs/screenshots/watch.svg from real watch frames
```

## How the code is organised

Start with [docs/architecture.md](docs/architecture.md). In short: parsers produce records, the
analyzer turns them into a **summary**, renderers turn a summary into text, JSON or HTML. Anything
that touches the outside world (files, clock, sleep, terminal) comes in as an argument so the
specs can fake it; see `spec/fakes.lua`.

## Tests

Tests live in `spec/` and use the small framework in `spec/support.lua` (`describe`, `it`, `eq`,
`contains`, ...). The runner lists the spec files in `spec/run.lua`, and undeclared globals are an error.

* Every change comes with a spec. Cover edge cases and hostile input, not just the happy path.
* Tests are deterministic: seeded random numbers (`tools/lcg.lua`), injected clocks, no network.
* Terminal frames are compared with golden files in `spec/fixtures/golden/`. After an intended
  change to the dashboard, regenerate them with `UPDATE_GOLDEN=1 lua spec/run.lua` and **read the
  diff**: it is the review of the new layout.
* New log formats need parser specs (well-formed, quoting, malformed, fuzz) and a line in
  `docs/formats.md`. New security heuristics need a signature spec, a bounds spec and entries in
  `docs/security-heuristics.md` (trigger, severity, limitations).

## Style

* `.editorconfig` and `.stylua.toml` apply: two spaces, LF, UTF-8 without BOM, double quotes.
* Small modules with one responsibility, LDoc comments on public functions, no global state, no
  dead code. Return errors with actionable messages instead of raising where a caller can recover.
* Validate input and bound resources (sizes, counts, time). Escape everything that goes to a terminal
  or a browser; never build HTML from data.
* `src/loglens/assets/` is the front end of the HTML report. `aurora.css`, `aurora.js` and
  `aurora-charts.js` are the bundled Aurora UI kit (zero dependencies, MIT, part of this repository);
  the report's own behaviour and styling belong in `report.js` and `report.css`. The kit files are
  small and may be edited with care. Keep the report's security rules, which the specs and the CSP
  depend on: no `innerHTML`, no inline `style` or `<script>`, colours only through the kit's custom
  properties, no external requests.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat: ...`, `fix: ...`,
`docs: ...`, `test: ...`, `refactor: ...`, `ci: ...`. Keep changes focused, describe how you tested
them in the pull request, and update `CHANGELOG.md` under `Unreleased` for user-visible changes.

Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
