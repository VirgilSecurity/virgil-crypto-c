# Build environment for Anthropic OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository as context; network access is removed afterwards,
# so everything needed to build, test and fuzz the C libraries must be fetched here.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    CC=clang \
    CXX=clang++
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential clang libclang-rt-14-dev llvm cmake ninja-build pkg-config git \
      python3 python3-venv protobuf-compiler gdb valgrind \
    && rm -rf /var/lib/apt/lists/*

# nanopb generator (protoc-gen-nanopb) and protobuf runtime used at configure/build time
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "protobuf>=5.28.3" "nanopb>=0.4.9"
ENV PATH=/opt/venv/bin:$PATH

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# 1) Regular build (common, foundation, ed25519, ratchet, phe + post-quantum) with unit tests.
RUN cmake -S /src -B /src/build -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer" \
      -DENABLE_CLANGFORMAT=OFF \
      -DVIRGIL_PROGRAMS=ON \
    && cmake --build /src/build -j"$(nproc)"

# 2) ASan/UBSan build of everything, plus the libFuzzer harnesses in tests/fuzzy/ (foundation key/ASN.1/DER
#    parsers and recipient_cipher decryption). The whole library is instrumented, not just the harnesses.
RUN cmake -S /src -B /src/build-asan -G Ninja \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize=fuzzer-no-link" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DENABLE_CLANGFORMAT=OFF \
      -DENABLE_FUZZY_TESTING=ON \
    && cmake --build /src/build-asan -j"$(nproc)"

# Run the cheap tests so the image is known to work, without letting a failure abort the build.
RUN cd /src/build && (ctest --output-on-failure -j"$(nproc)" --timeout 300 || echo "WARNING: ctest reported failures")
RUN cd /src/build-asan && (ctest --output-on-failure -j"$(nproc)" --timeout 300 -E '^fuzzy_test__' \
      || echo "WARNING: ASan ctest reported failures")
