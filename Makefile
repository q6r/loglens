# Developer shortcuts. Everything also works without make: see CONTRIBUTING.md.
LUA ?= lua

.PHONY: test lint format check-format examples recording

test: ## run the spec suite
	$(LUA) spec/run.lua

lint: ## luacheck over the sources, specs, tools and the CLI
	luacheck src spec tools bin/loglens

format: ## format with stylua
	stylua .

check-format: ## verify formatting without changing files
	stylua --check .

examples: ## regenerate examples/ (deterministic)
	$(LUA) tools/gen_examples.lua

recording: ## regenerate docs/screenshots/watch.svg from real frames of the watch loop
	$(LUA) tools/make_recording.lua
