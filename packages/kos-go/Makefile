# Detect OS and Architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
	GOOS := linux
	LIB_EXT := .so
	LIB_PATH_VAR := LD_LIBRARY_PATH
endif
ifeq ($(UNAME_S),Darwin)
	GOOS := darwin
	LIB_EXT := .dylib
	LIB_PATH_VAR := DYLD_LIBRARY_PATH
endif

ifeq ($(UNAME_M),x86_64)
	GOARCH := amd64
endif
ifeq ($(UNAME_M),arm64)
	GOARCH := arm64
endif
ifeq ($(UNAME_M),aarch64)
	GOARCH := arm64
endif

ifeq ($(GOOS),darwin)
	ifeq ($(GOARCH),arm64)
		LIB_DIR := kos_mobile/lib/darwin-aarch64
	else
		LIB_DIR := kos_mobile/lib/darwin-$(GOARCH)
	endif
else
	LIB_DIR := kos_mobile/lib/$(GOOS)-$(GOARCH)
endif

CGO_ENABLED := 1
BUILD_FLAGS := -v
TEST_FLAGS := -v

.PHONY: all
all: test

.PHONY: info
info:
	@echo "Detected Configuration:"
	@echo "  OS: $(GOOS)"
	@echo "  ARCH: $(GOARCH)"
	@echo "  Library Directory: $(LIB_DIR)"
	@echo "  Library Path Variable: $(LIB_PATH_VAR)"

.PHONY: test
test: info
	@echo "Running tests..."
	$(LIB_PATH_VAR)=$(PWD)/$(LIB_DIR) \
	CGO_ENABLED=$(CGO_ENABLED) \
	GOOS=$(GOOS) \
	GOARCH=$(GOARCH) \
	go test $(TEST_FLAGS) ./...

.PHONY: build
build: info
	@echo "Building..."
	$(LIB_PATH_VAR)=$(PWD)/$(LIB_DIR) \
	CGO_ENABLED=$(CGO_ENABLED) \
	GOOS=$(GOOS) \
	GOARCH=$(GOARCH) \
	go build $(BUILD_FLAGS) ./...

.PHONY: clean
clean:
	@echo "Cleaning..."
	go clean ./...
	rm -f *.so *.dylib

.PHONY: build-linux-amd64
build-linux-amd64:
	LD_LIBRARY_PATH=$(PWD)/kos_mobile/lib/linux-amd64 \
	CGO_ENABLED=1 \
	GOOS=linux \
	GOARCH=amd64 \
	go build $(BUILD_FLAGS) -o bin/kos-linux-amd64 ./...

.PHONY: build-darwin-arm64
build-darwin-arm64:
	DYLD_LIBRARY_PATH=$(PWD)/kos_mobile/lib/darwin-aarch64 \
	CGO_ENABLED=1 \
	GOOS=darwin \
	GOARCH=arm64 \
	go build $(BUILD_FLAGS) -o bin/kos-darwin-arm64 ./...

.PHONY: test-linux-amd64
test-linux-amd64:
	LD_LIBRARY_PATH=$(PWD)/kos_mobile/lib/linux-amd64 \
	CGO_ENABLED=1 \
	GOOS=linux \
	GOARCH=amd64 \
	go test $(TEST_FLAGS) ./...

.PHONY: test-darwin-arm64
test-darwin-arm64:
	DYLD_LIBRARY_PATH=$(PWD)/kos_mobile/lib/darwin-aarch64 \
	CGO_ENABLED=1 \
	GOOS=darwin \
	GOARCH=arm64 \
	go test $(TEST_FLAGS) ./...

.PHONY: build-all
build-all: build-linux-amd64 build-darwin-arm64
	@echo "Built all platforms"

.PHONY: test-all
test-all:
	@echo "Testing all available platforms..."
	@if [ -d "kos_mobile/lib/linux-amd64" ]; then \
		echo "Testing Linux AMD64..."; \
		$(MAKE) test-linux-amd64; \
	fi
	@if [ -d "kos_mobile/lib/darwin-aarch64" ]; then \
		echo "Testing Darwin ARM64..."; \
		$(MAKE) test-darwin-arm64; \
	fi

.PHONY: check-lib
check-lib:
	@echo "Checking for library at: $(LIB_DIR)/libkos_mobile$(LIB_EXT)"
	@if [ -f "$(LIB_DIR)/libkos_mobile$(LIB_EXT)" ]; then \
		echo "✓ Library found"; \
		ls -la $(LIB_DIR)/libkos_mobile$(LIB_EXT); \
	else \
		echo "✗ Library not found at $(LIB_DIR)/libkos_mobile$(LIB_EXT)"; \
		echo "Available libraries:"; \
		find kos_mobile/lib -name "libkos_mobile*" 2>/dev/null || echo "No libraries found"; \
		exit 1; \
	fi

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  info          - Show detected OS/ARCH configuration"
	@echo "  test          - Run tests for current platform"
	@echo "  build         - Build for current platform"
	@echo "  clean         - Clean build artifacts"
	@echo "  check-lib     - Verify library exists for current platform"
	@echo ""
	@echo "Cross-platform targets:"
	@echo "  build-all           - Build for all platforms"
	@echo "  build-linux-amd64   - Build for Linux AMD64"
	@echo "  build-darwin-arm64  - Build for macOS ARM64"
	@echo "  test-all            - Test all available platforms"
	@echo "  test-linux-amd64    - Test Linux AMD64"
	@echo "  test-darwin-amd64   - Test macOS AMD64"
	@echo "  test-darwin-arm64   - Test macOS ARM64"