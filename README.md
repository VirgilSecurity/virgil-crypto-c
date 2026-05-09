[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)

# Virgil Security Crypto Library for C

[![Build Linux](https://github.com/VirgilSecurity/virgil-crypto-c/actions/workflows/build-linux.yml/badge.svg)](https://github.com/VirgilSecurity/virgil-crypto-c/actions/workflows/build-linux.yml)
[![Build macOS](https://github.com/VirgilSecurity/virgil-crypto-c/actions/workflows/build-macos.yml/badge.svg)](https://github.com/VirgilSecurity/virgil-crypto-c/actions/workflows/build-macos.yml)
[![Swift Package Manager](https://img.shields.io/badge/Swift_Package_Manager-compatible-orange?style=flat)](https://www.swift.org/package-manager/)


## Introduction

This library is designed to be a small, flexible and convenient wrapper for a variety of crypto algorithms.
So it can be used in a small microcontroller as well as in a high load server application. Also, it provides several custom hybrid algorithms that combine different crypto algorithms to solve common complex cryptographic problems in an easy way. This eliminates the requirement for developers to have strong cryptographic skills.

The library is available for different platforms and contains wrappers for other languages.

## Features

The Virgil Security Crypto C library is decomposed into small libraries with specific purposes. A developer can freely choose a subset of libraries.

### Library: Foundation

This library contains basic cryptographic algorithms and can be used as building blocks for complex solutions.

| Algorithm Purpose           | Implementation details                                                                                                                                                           |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Key Generation, PRNG        | CTR_DRBG [NIST SP 800-90A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)                                                                           |
| Key Derivation              | [KDF1, KDF2](https://www.shoup.net/iso/std6.pdf),  [HKDF](https://tools.ietf.org/html/rfc5869), [PBKDF2](https://tools.ietf.org/html/rfc8018#section-5.2)                        |
| Key Exchange                | [X25519](https://tools.ietf.org/html/rfc7748), [RSA](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf), [ECDH](https://www.secg.org/sec1-v2.pdf)       |
| Key Encapsulation Mechanism | [Round5](https://github.com/round5/code), ECIES-KEM                                                                                                                              |
| Hashing                     | [SHA-2 (224/256/384/512)](https://tools.ietf.org/html/rfc4634)                                                                                                                   |
| Message Authentication Code | [HMAC](https://www.ietf.org/rfc/rfc2104.txt)                                                                                                                                     |
| Digital Signature           | [Ed25519](https://tools.ietf.org/html/rfc8032), [RSASSA-PSS](https://tools.ietf.org/html/rfc4056), [ECDSA](https://www.secg.org/sec1-v2.pdf), [Falcon](https://falcon-sign.info) |
| Entropy Source              | Linux, macOS [/dev/urandom](https://tls.mbed.org/module-level-design-rng),<br>Windows [CryptGenRandom()](https://tls.mbed.org/module-level-design-rng)                           |
| Symmetric Algorithms        | [AES-256-GCM](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), [AES-256-CBC](https://tools.ietf.org/html/rfc3602)                                  |
| Encryption schemes          | [PBES2](https://tools.ietf.org/html/rfc8018#section-6.2)                                                                                                                         |
| Elliptic Curves             | [Ed25519](https://tools.ietf.org/html/rfc8032), [Curve25519](https://tools.ietf.org/html/rfc7748), [secp256R1](https://www.secg.org/sec1-v2.pdf)                                 |
| Post-quantum cryptography   | [Falcon](https://falcon-sign.info), [Round5](https://github.com/round5/code)                                                                                                     |

### Library: PHE

The cryptographic background for the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers the technology to protect user passwords from offline attacks and render stolen passwords useless even if your database has been compromised. The service implementation can be found [here](https://github.com/VirgilSecurity/virgil-phe-go).

### Library: Ratchet

Implementation of the [Double Ratchet Algorithm](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm).


## Platforms & languages

| Library    | Platforms    | Languages / Binaries                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| foundation | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [Swift](https://github.com/VirgilSecurity/virgil-cryptowrapper-x), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib), [Go](https://github.com/VirgilSecurity/virgil-sdk-go/tree/master/crypto/internal), [PHP](https://github.com/VirgilSecurity/virgil-cryptowrapper-php) |
| phe        | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [PHP](https://cdn.virgilsecurity.com/virgil-crypto-c/php), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib), [Go](https://github.com/VirgilSecurity/virgil-sdk-go/tree/master/crypto/internal), [PHP](https://github.com/VirgilSecurity/virgil-cryptowrapper-php)         |
| ratchet    | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [Swift](https://github.com/VirgilSecurity/virgil-cryptowrapper-x), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib), [Go](https://github.com/VirgilSecurity/virgil-sdk-go/tree/master/crypto/internal)                                                                    |

## Build from sources

### Prerequisites

* Compiler:
  - `gcc` (version >= 4.8.2), or
  - `clang` (version >= 3.6), or
  - `msvc` (version >= 14.0)
* Build tools:
  - `cmake` (version >= 3.12)
  - `python` (version >= 3)
  - `python-protobuf`

### Build & Install

```bash
git clone https://github.com/VirgilSecurity/virgil-crypto-c.git
cd virgil-crypto-c
cmake -Bbuild -S.
cmake --build build
cmake --build build --target install
```

## Run Benchmarks

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_BENCHMARKING=ON \
      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
      -Bbuild -S.

cmake --build build -- -j10

./build/benchmarks/foundation/bench
```

## Releasing

Releases are fully automated through CI. No local builds required.

### How to cut a release

Trigger the unified release workflow via the `/release` skill in Claude Code, or directly with `gh`:

```bash
gh workflow run release.yml \
  --field version=0.19.0 \
  --field branch=develop
```

Version format: bare `MAJOR.MINOR.PATCH` for production or `MAJOR.MINOR.PATCH-LABEL` for pre-releases (e.g. `0.19.0-dev.7`, `0.19.0-rc1`). No leading `v` — the workflow adds that.

### What the workflow does

| Stage | Action |
|-------|--------|
| `validate` | Rejects malformed version strings immediately |
| `build-go` (parallel) | Cross-compiles static libs for 5 platforms (linux amd64/arm64, darwin amd64/arm64, windows amd64) |
| `build-apple` (parallel) | Builds Apple xcframeworks on macOS |
| `release-commit` | Bumps version across all wrappers, merges all compiled artifacts, verifies xcframework checksums, runs `swift build` + `swift test`, commits binaries to the source branch, pushes both the Go module tag (`wrappers/go/vX.Y.Z`) and the release tag (`vX.Y.Z`) atomically |

The release tag then triggers downstream workflows that publish to PyPI, Maven Central, npm, GitHub Releases, and PHP repositories.

### Incompatible change from previous releases

`release-go.yml` has been removed. It previously compiled Go static libs in response to `v*` tag pushes. That tag-triggered behavior no longer exists — Go lib compilation is now part of `release.yml`. Downstream repositories or scripts that depended on `release-go.yml` running on tag pushes will see no effect from tags created by the new workflow. The Go static libs are bundled into the release commit before the tag is created.

## Support

Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

## License

BSD 3-Clause. See [LICENSE](LICENSE) for details.
