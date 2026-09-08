# ── Per-worktree toolchain staging ───────────────────────────────────────
#
# A BDD run must exercise THIS worktree's insomnia together with one known
# zebra-rs toolchain. Left to themselves the daemons and CLIs resolve
# host-global paths (/usr/bin/zebra-rs, /usr/bin/vtyctl, /usr/bin/insomnia,
# /usr/share/zebra-rs/yang), which any `make install` overwrites — so a run
# silently tests whichever binary was installed last.
#
# `stage` builds this worktree's insomnia and copies it, together with the
# zebra-rs toolchain found under $(ZEBRA_PREFIX), into `.stage/`, mirroring
# the /usr layout. The harness picks it up automatically (see
# bdd/src/toolchain.rs) and reads nothing under /usr. Every test target
# below runs `stage` first, so it is impossible to test a stale binary
# through make.
#
# ZEBRA_PREFIX is any tree laid out like /usr — the installed package
# (default), or a zebra-rs worktree's own stage
# (`make -C bdd stage ZEBRA_PREFIX=../../zebra-rs/bdd/.stage`) to test
# against an unreleased zebra-rs.
#
# Copies, not symlinks into target/: cargo rewrites target/<profile>/insomnia
# in place, so a rebuild during a run would otherwise swap the binary out
# from under it.
PROFILE ?= release
CARGO_PROFILE_FLAG := $(if $(filter release,$(PROFILE)),--release,)
TARGET_DIR ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),../target)
STAGE := .stage
ZEBRA_PREFIX ?= /usr
# The zebra-rs side the features drive: the daemon, the CLI that applies
# config and runs shows, and the helper the daemon spawns for the vty.
ZEBRA_BINS := zebra-rs vtyctl vtyhelper

# Every cucumber invocation goes through this, so staging can never be
# skipped by running a target directly.
CUCUMBER = $(MAKE) --no-print-directory stage && cargo test --test cucumber

.DEFAULT_GOAL := all

# Populates a scratch directory and renames it into place, so an interrupted
# stage never leaves a half-filled .stage behind — the harness refuses to run
# against one rather than silently falling back to /usr.
.PHONY: stage
stage:
	cargo build $(CARGO_PROFILE_FLAG) -p insomnia
	@for b in $(ZEBRA_BINS); do \
	    [ -x "$(ZEBRA_PREFIX)/bin/$$b" ] || { \
	        echo "error: $(ZEBRA_PREFIX)/bin/$$b not found — install zebra-rs or pass ZEBRA_PREFIX=<tree laid out like /usr>"; \
	        exit 1; }; \
	done
	@[ -d "$(ZEBRA_PREFIX)/share/zebra-rs/yang" ] || { \
	    echo "error: $(ZEBRA_PREFIX)/share/zebra-rs/yang not found"; exit 1; }
	@rm -rf $(STAGE).tmp
	@mkdir -p $(STAGE).tmp/bin $(STAGE).tmp/share/zebra-rs/yang
	@install -m 0755 $(TARGET_DIR)/$(PROFILE)/insomnia $(STAGE).tmp/bin/
	@install -m 0755 $(addprefix $(ZEBRA_PREFIX)/bin/,$(ZEBRA_BINS)) $(STAGE).tmp/bin/
	@install -m 0644 $(ZEBRA_PREFIX)/share/zebra-rs/yang/*.yang $(STAGE).tmp/share/zebra-rs/yang/
	@rm -rf $(STAGE)
	@mv $(STAGE).tmp $(STAGE)
	@echo "[staged $(PROFILE) insomnia + zebra-rs from $(ZEBRA_PREFIX) in $(CURDIR)/$(STAGE)]"

# Drop the staged toolchain; subsequent runs fall back to the host-global
# /usr layout (i.e. pre-staging behavior).
.PHONY: unstage
unstage:
	rm -rf $(STAGE) $(STAGE).tmp

all:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=16

run:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1

# Site-to-site IPsec: requires charon-systemd + strongswan-swanctl
# installed on the host (apt install charon-systemd strongswan-swanctl)
# — see the feature header and tests/scripts/ipsec_node.sh.
ipsec_s2s:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@ipsec_s2s"

# VRRP master/backup pair: requires keepalived installed on the host
# (apt install keepalived) — see the feature header and
# tests/scripts/vrrp_node.sh.
vrrp_pair:
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@vrrp_pair"

generate:
	rm -rf allure-report
	allure generate

open:
	rm -rf allure-report
	allure generate
	allure open

FEATURE_FILES := $(wildcard tests/features/*.feature)
DOC_FILES     := $(patsubst tests/features/%.feature,docs/%.md,$(FEATURE_FILES))

# Every page under docs/ is generated from a feature, so a page with
# no feature behind it is stale: `make docs` can neither refresh it nor
# notice it has gone wrong. Fail rather than leave one sitting there
# looking as maintained as the rest.
docs: $(DOC_FILES)
	@orphans=$$(for d in docs/*.md; do \
	    [ -e "$$d" ] || continue; \
	    b=$$(basename "$$d" .md); \
	    [ -f "tests/features/$$b.feature" ] || echo "  $$d"; \
	done); \
	if [ -n "$$orphans" ]; then \
	    echo "error: docs/ pages with no tests/features/<name>.feature:"; \
	    echo "$$orphans"; \
	    echo "delete them, or restore the feature they document."; \
	    exit 1; \
	fi

docs/%.md: tests/features/%.feature docs/feature2md.sh FORCE
	docs/feature2md.sh $< $@

FORCE:

.PHONY: all run ipsec_s2s vrrp_pair generate open docs FORCE
