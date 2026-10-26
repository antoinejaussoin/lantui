# Cross-build lantui for the current Mac, Linux x64, and Linux arm64.
# From macOS you need rustup and zig (`brew install zig`).
# From Linux, `make linux` builds the two Linux targets (Mac is skipped).

DIST        := dist
MAC_TRIPLE  := aarch64-apple-darwin
LIN_X64     := x86_64-unknown-linux-gnu
LIN_ARM64   := aarch64-unknown-linux-gnu

CARGO       ?= cargo
HOST_OS     := $(shell uname -s)
# Keep cross artifacts out of ./target so a `sudo cargo run` lock cannot block `make`.
export CARGO_TARGET_DIR := $(CURDIR)/.cross-target

export CC_x86_64_unknown_linux_gnu   := $(CURDIR)/scripts/zig-cc-x86_64-linux-gnu
export CXX_x86_64_unknown_linux_gnu  := $(CURDIR)/scripts/zig-cc-x86_64-linux-gnu
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER := $(CURDIR)/scripts/zig-cc-x86_64-linux-gnu
export CC_aarch64_unknown_linux_gnu  := $(CURDIR)/scripts/zig-cc-aarch64-linux-gnu
export CXX_aarch64_unknown_linux_gnu := $(CURDIR)/scripts/zig-cc-aarch64-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER := $(CURDIR)/scripts/zig-cc-aarch64-linux-gnu

.PHONY: all dist macos linux linux-x64 linux-arm64 setup clean help

all: dist

help:
	@echo "make          build Mac + Linux x64 + Linux arm64 into $(DIST)/"
	@echo "make linux    build only the Linux targets"
	@echo "make macos    build only the Mac target"
	@echo "make setup    install rustup targets (and check zig)"
	@echo "make clean    remove $(DIST)/ and cargo artifacts"

dist: setup
ifeq ($(HOST_OS),Darwin)
	$(MAKE) macos linux
else
	@echo "not on macOS; building Linux targets only"
	$(MAKE) linux
endif
	@echo
	@echo "binaries in $(DIST)/"
	@ls -lh $(DIST)

setup:
	@command -v rustup >/dev/null || { echo "rustup is required"; exit 1; }
	@command -v zig >/dev/null || { echo "zig is required (brew install zig)"; exit 1; }
	@chmod +x scripts/zig-cc scripts/zig-cc-x86_64-linux-gnu scripts/zig-cc-aarch64-linux-gnu
	rustup target add $(MAC_TRIPLE) $(LIN_X64) $(LIN_ARM64)

macos:
	$(CARGO) build --release --target $(MAC_TRIPLE)
	@mkdir -p $(DIST)
	cp $(CARGO_TARGET_DIR)/$(MAC_TRIPLE)/release/lantui $(DIST)/lantui-macos-arm64
	@chmod +x $(DIST)/lantui-macos-arm64

linux: linux-x64 linux-arm64

linux-x64:
	$(CARGO) build --release --target $(LIN_X64)
	@mkdir -p $(DIST)
	cp $(CARGO_TARGET_DIR)/$(LIN_X64)/release/lantui $(DIST)/lantui-linux-x64
	@chmod +x $(DIST)/lantui-linux-x64

linux-arm64:
	$(CARGO) build --release --target $(LIN_ARM64)
	@mkdir -p $(DIST)
	cp $(CARGO_TARGET_DIR)/$(LIN_ARM64)/release/lantui $(DIST)/lantui-linux-arm64
	@chmod +x $(DIST)/lantui-linux-arm64

clean:
	rm -rf $(DIST) $(CARGO_TARGET_DIR)
