PATH := $(HOME)/.cargo/bin:$(PATH)

BINARY := cimg
TARGET := target/release/$(BINARY)
INSTALL_DIR := /usr/local/bin

.PHONY: all check-cargo build install

all: check-cargo build install

check-cargo:
	@echo "🔍 Checking for cargo..."
	@if ! command -v cargo > /dev/null; then \
		echo "Error: Cargo not found in PATH."; \
		echo "Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		echo "Sourcing Cargo env file..."; \
		. "$$HOME/.cargo/env"; \
	fi; \
	if ! command -v cargo > /dev/null; then \
		echo "❌ Still can't find cargo. Aborting."; \
		exit 1; \
	else \
		echo "✅ Cargo found at $$(which cargo)"; \
	fi


build:
	@echo "🔧 Building $(BINARY)..."
	cargo build --release

install:
	@echo "📦 Installing $(BINARY) to $(INSTALL_DIR)..."
	sudo install -m 755 $(TARGET) $(INSTALL_DIR)
	@echo "🚀 Installed! You can now run '$(BINARY)' from anywhere."
