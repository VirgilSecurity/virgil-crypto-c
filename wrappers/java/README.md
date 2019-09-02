[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)

# Java wrapper for Virgil Security Crypto Library for C

## Build from sources

### Prerequisites

  - `JDK` 8+
  - `maven` 3.5.0+

### Build & Install

Build native libraries and JNI libraries for your platform:

- linux
- macos
- windows

From the project's root directory

```bash
export PLATFORM=linux

cmake -DCMAKE_BUILD_TYPE=Release \
      -Cconfigs/java-config.cmake \
      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/${PLATFORM}" \
      -DENABLE_CLANGFORMAT=OFF \
      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
      -Bbuild -H.

cmake --build build --target install -- -j10
```

From the `wrappers/java` directoty

```bash
mvn clean package
```

## Run benchmarks

Build artifacts with a command
```bash
mvn clean install
```

A JAR file with benchmarks and all dependencies will be build. You can find it at `benchmark/target/benchmark.jar`.
You can copy this JAR file to any other machine with install JRE and run with a command
```bash
java -jar <path_to_jar>
```

## License

BSD 3-Clause. See [LICENSE](../../LICENSE) for details.
