# VirgilCryptoC — Build & Test
#
# Usage:
#   make build          Build C libraries
#   make test           Run C tests
#   make build-go       Build Go wrapper (native libs + go build)
#   make test-go        Build + test Go wrapper
#   make build-python   Build Python wrapper (native libs for wheel)
#   make test-python    Build + test Python wrapper
#   make build-php      Build PHP wrapper
#   make test-php       Build + test PHP wrapper
#   make build-wasm     Build WASM wrapper (requires Emscripten)
#   make test-wasm      Build + test WASM wrapper
#   make build-all      Build everything
#   make test-all       Run all tests
#   make clean          Remove build directories
#   make help           Show this help

.PHONY: help build test clean \
        build-go test-go \
        build-python test-python \
        build-php test-php \
        build-wasm test-wasm \
        build-all test-all

# Detect platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
NPROC := $(shell if command -v nproc >/dev/null 2>&1; then nproc; else sysctl -n hw.physicalcpu; fi)

ifeq ($(UNAME_S),Darwin)
  GO_OS := darwin
else ifeq ($(UNAME_S),Linux)
  GO_OS := linux
else
  GO_OS := windows
endif

ifeq ($(UNAME_M),arm64)
  GO_ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
  GO_ARCH := arm64
else
  GO_ARCH := amd64
endif

BUILD_TYPE ?= Release

# ---------------------------------------------------------------------------
#   C library
# ---------------------------------------------------------------------------

build:
	@echo "==> Building C libraries ($(BUILD_TYPE))"
	cmake -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DENABLE_CLANGFORMAT=OFF -Bbuild -S.
	cmake --build build -j$(NPROC)

test: build
	@echo "==> Running C tests"
	cd build && ctest --output-on-failure -j$(NPROC)

# ---------------------------------------------------------------------------
#   Go wrapper
# ---------------------------------------------------------------------------

build-go:
	@echo "==> Building Go wrapper ($(GO_OS)/$(GO_ARCH))"
	cmake -Cconfigs/go-config.cmake \
		-DVIRGIL_WRAP_GO=OFF \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_INSTALL_PREFIX="wrappers/go/pkg/$(GO_OS)_$(GO_ARCH)" \
		-DENABLE_CLANGFORMAT=OFF \
		-DVIRGIL_POST_QUANTUM=ON \
		-Bbuild-go -S.
	cmake --build build-go --target install -j$(NPROC)

test-go: build-go
	@echo "==> Running Go tests"
	cd wrappers/go && go test ./...

# ---------------------------------------------------------------------------
#   Python wrapper
# ---------------------------------------------------------------------------

build-python:
	@echo "==> Building Python wrapper"
	cmake -Cconfigs/python-config.cmake \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_INSTALL_PREFIX=wrappers/python/virgil_crypto_lib \
		-DCMAKE_INSTALL_LIBDIR=_libs \
		-DENABLE_CLANGFORMAT=OFF \
		-Bbuild-python -S.
ifeq ($(UNAME_S),Darwin)
	cmake -DCMAKE_INSTALL_RPATH=@loader_path -Bbuild-python
endif
	cmake --build build-python --target install -j$(NPROC)

test-python: build-python
	@echo "==> Running Python tests"
	cd wrappers/python && python3 -c " \
		from virgil_crypto_lib.foundation.sha256 import Sha256; \
		h = Sha256().hash(bytearray(b'test')); \
		assert len(h) == 32, 'SHA-256 failed'; \
		print('Python smoke test OK')"

# ---------------------------------------------------------------------------
#   PHP wrapper
# ---------------------------------------------------------------------------

build-php:
	@echo "==> Building PHP wrapper"
	cmake -Cconfigs/php-config.cmake \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DENABLE_CLANGFORMAT=OFF \
		-Bbuild-php -S.
	cmake --build build-php -j$(NPROC)

test-php: build-php
	@echo "==> Running PHP tests"
	cd wrappers/php && composer install --no-interaction && vendor/bin/phpunit

# ---------------------------------------------------------------------------
#   WASM wrapper
# ---------------------------------------------------------------------------

build-wasm:
	@echo "==> Building WASM wrapper (requires Emscripten)"
	@if [ -z "$$EMSDK" ]; then echo "ERROR: EMSDK not set. Install and activate Emscripten first."; exit 1; fi
	emcmake cmake -Cconfigs/wasm-config.cmake \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DENABLE_CLANGFORMAT=OFF \
		-Bbuild-wasm -S.
	cmake --build build-wasm -j$(NPROC)

test-wasm: build-wasm
	@echo "==> Running WASM tests"
	cd wrappers/wasm && npm ci && npm run prepare && npm test

# ---------------------------------------------------------------------------
#   Aggregate targets
# ---------------------------------------------------------------------------

build-all: build build-go build-python build-php
	@echo "==> All builds complete"

test-all: test test-go test-python test-php
	@echo "==> All tests complete"

# ---------------------------------------------------------------------------
#   Cleanup
# ---------------------------------------------------------------------------

clean:
	rm -rf build build-go build-python build-php build-wasm
	rm -rf wrappers/go/pkg/$(GO_OS)_$(GO_ARCH)
	rm -rf wrappers/python/virgil_crypto_lib/_libs/*.so
	rm -rf wrappers/python/virgil_crypto_lib/_libs/*.dylib
	rm -rf wrappers/python/virgil_crypto_lib/_libs/*.dll
	@echo "==> Clean complete"

# ---------------------------------------------------------------------------
#   Help
# ---------------------------------------------------------------------------

help:
	@echo "VirgilCryptoC Build & Test"
	@echo ""
	@echo "C library:"
	@echo "  make build           Build C libraries"
	@echo "  make test            Build + run C tests"
	@echo ""
	@echo "Wrappers:"
	@echo "  make build-go        Build Go wrapper (native libs)"
	@echo "  make test-go         Build + test Go wrapper"
	@echo "  make build-python    Build Python wrapper (native libs)"
	@echo "  make test-python     Build + smoke test Python wrapper"
	@echo "  make build-php       Build PHP wrapper"
	@echo "  make test-php        Build + test PHP wrapper"
	@echo "  make build-wasm      Build WASM wrapper (requires Emscripten)"
	@echo "  make test-wasm       Build + test WASM wrapper"
	@echo ""
	@echo "Aggregate:"
	@echo "  make build-all       Build C + all wrappers"
	@echo "  make test-all        Test C + all wrappers"
	@echo ""
	@echo "Other:"
	@echo "  make clean           Remove all build directories"
	@echo "  make help            Show this help"
	@echo ""
	@echo "Options:"
	@echo "  BUILD_TYPE=Debug     Set CMake build type (default: Release)"
