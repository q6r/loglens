-- luacheck configuration (https://github.com/lunarmodules/luacheck):
--   luacheck src spec tools bin/loglens
std = "lua53"
max_line_length = false -- layout is stylua's job, see .stylua.toml
codes = true

-- The bundled UI kit and the report view (src/loglens/assets) are JavaScript and CSS, not Lua.
exclude_files = { "src/loglens/assets/**" }

-- `_` marks values that are deliberately unused, and a method that implements an interface (the fakes
-- in spec/) often has no use for `self`.
ignore = { "212/_.*", "213/_.*", "212/self" }
