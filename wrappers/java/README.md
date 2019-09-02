[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)

# Java wrapper for Virgil Security Crypto Library for C

## Build from sources

### Prerequisites

  - `JDK` 8+
  - `maven` 3.5.0+

### Build & Install

Build native libraries. See [readme](https://github.com/VirgilSecurity/virgil-crypto-c/blob/master/README.md) for details.
Build Java JNI library for your platform

```bash
mvn clean package
```

## Run benchmarks

Build artifacts with a command
```bash
mvn clean install
```

A JAR file with benchmarks and all dependencies will be build. You can find it at `/benchmark/target/benchmark.jar`.
You can copy this JAR file to any other machine with install JRE and run with a command
```bash
java -jar <path_to_jar>
```

## License

BSD 3-Clause. See [LICENSE](../../LICENSE) for details.
