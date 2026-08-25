# StartOS package build plumbing.
# Keep edits in Makefile; this file mirrors the Start9 package template.

PACKAGE_ID := $(shell awk -F"'" '/id:/ {print $$2}' startos/manifest/index.ts)
INGREDIENTS := $(shell start-cli s9pk list-ingredients 2>/dev/null)
DOCKER_CONTEXT_DEPS := $(shell git ls-files -- .dockerignore Cargo.toml Cargo.lock crates vendor/cashu-service web/control-panel umbrel/Dockerfile 2>/dev/null)
PACKAGE_DEPS := $(sort $(INGREDIENTS) $(DOCKER_CONTEXT_DEPS))
GIT_DIR := $(shell git rev-parse --git-dir 2>/dev/null)
GIT_DEPS := $(if $(GIT_DIR),$(GIT_DIR)/HEAD $(GIT_DIR)/index)
ARCHES ?= x86 arm riscv
TARGETS ?= $(ARCHES)

ifdef VARIANT
BASE_NAME := $(PACKAGE_ID)_$(VARIANT)
else
BASE_NAME := $(PACKAGE_ID)
endif

.PHONY: all arches aarch64 x86_64 riscv64 arm arm64 x86 riscv arch/% clean install check-deps check-init package ingredients
.DELETE_ON_ERROR:
.SECONDARY:

define SUMMARY
	@manifest=$$(start-cli s9pk inspect $(1) manifest); \
	size=$$(du -h $(1) | awk '{print $$1}'); \
	title=$$(printf '%s' "$$manifest" | jq -r .title); \
	version=$$(printf '%s' "$$manifest" | jq -r .version); \
	arches=$$(printf '%s' "$$manifest" | jq -r '[.images[].arch // []] | flatten | unique | join(", ")'); \
	sdkv=$$(printf '%s' "$$manifest" | jq -r .sdkVersion); \
	gitHash=$$(printf '%s' "$$manifest" | jq -r .gitHash | sed -E 's/(.*-modified)$$/\x1b[0;31m\1\x1b[0m/'); \
	printf "\n"; \
	printf "\033[1;32mBuild complete\033[0m\n"; \
	printf "\n"; \
	printf "\033[1;37m$$title\033[0m   \033[36mv$$version\033[0m\n"; \
	printf "%s\n" "------------------------------"; \
	printf "Filename:   %s\n" "$(1)"; \
	printf "Size:       %s\n" "$$size"; \
	printf "Arch:       %s\n" "$$arches"; \
	printf "SDK:        %s\n" "$$sdkv"; \
	printf "Git:        %s\n" "$$gitHash"; \
	echo ""
endef

all: $(TARGETS)

arches: $(ARCHES)

print-%:
	@echo '$($*)'

universal: $(BASE_NAME).s9pk
	$(call SUMMARY,$<)

arch/%: $(BASE_NAME)_%.s9pk
	$(call SUMMARY,$<)

x86 x86_64: arch/x86_64
arm arm64 aarch64: arch/aarch64
riscv riscv64: arch/riscv64

$(BASE_NAME).s9pk: $(PACKAGE_DEPS) $(GIT_DEPS)
	@$(MAKE) --no-print-directory ingredients
	@echo "   Packing '$@'..."
	start-cli s9pk pack -o $@

$(BASE_NAME)_%.s9pk: $(PACKAGE_DEPS) $(GIT_DEPS)
	@$(MAKE) --no-print-directory ingredients
	@echo "   Packing '$@'..."
	start-cli s9pk pack --arch=$* -o $@

ingredients: $(INGREDIENTS)
	@echo "   Re-evaluating ingredients..."

install: | check-deps check-init
	@HOST=$$(awk -F'/' '/^host:/ {print $$3}' ~/.startos/config.yaml); \
	if [ -z "$$HOST" ]; then \
		echo "Error: define host in ~/.startos/config.yaml"; \
		exit 1; \
	fi; \
	S9PK=$$(ls -t *.s9pk 2>/dev/null | head -1); \
	if [ -z "$$S9PK" ]; then \
		echo "Error: no .s9pk file found. Run 'make' first."; \
		exit 1; \
	fi; \
	printf "\nInstalling %s to %s ...\n" "$$S9PK" "$$HOST"; \
	start-cli package install -s "$$S9PK"

check-deps:
	@command -v start-cli >/dev/null || \
		(echo "Error: start-cli not found. See https://docs.start9.com/packaging/0.4.0.x/environment-setup.html" && exit 1)
	@command -v npm >/dev/null || \
		(echo "Error: npm not found. Please install Node.js and npm." && exit 1)

check-init:
	@if [ ! -f ~/.startos/developer.key.pem ]; then \
		echo "Initializing StartOS developer environment..."; \
		start-cli init-key; \
	fi

javascript/index.js: $(shell find startos -type f) tsconfig.json node_modules
	npm run check
	npm run build

node_modules: package-lock.json
	npm ci

package-lock.json: package.json
	npm i

clean:
	@echo "Cleaning StartOS build artifacts..."
	@rm -rf $(PACKAGE_ID).s9pk $(PACKAGE_ID)_x86_64.s9pk $(PACKAGE_ID)_aarch64.s9pk $(PACKAGE_ID)_riscv64.s9pk javascript node_modules
