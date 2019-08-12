[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)

# Virgil Security Crypto Library for C

| branch  | build                                                                                                                                            |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| master  | [![Build Status](https://travis-ci.com/VirgilSecurity/virgil-crypto-c.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-c)  |
| develop | [![Build Status](https://travis-ci.com/VirgilSecurity/virgil-crypto-c.svg?branch=develop)](https://travis-ci.com/VirgilSecurity/virgil-crypto-c) |


## Introduction

This library is designed to be a small, flexible and convenient wrapper for a variety of crypto algorithms.
So it can be used in a small microcontroller as well as in a high load server application. Also, it provides several custom hybrid algorithms that combine different crypto algorithms to solve common complex cryptographic problems in an easy way. This eliminates the requirement for developers to have strong cryptographic skills.

The library is available for different platforms and contains wrappers for other languages.

## Features

The Virgil Security Crypto C library is decomposed into small libraries with specific purposes. A developer can freely choose a subset of libraries.

### Library: Foundation

This library contains basic cryptographic algorithms and can be used as building blocks for complex solutions.

| Algorithm Purpose           | Implementation details                                       |
| --------------------------- | ------------------------------------------------------------ |
| Key Generation, PRNG        | CTR_DRBG [NIST SP 800-90A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf) |
| Key Derivation              | [KDF1, KDF2](https://www.shoup.net/iso/std6.pdf),  [HKDF](https://tools.ietf.org/html/rfc5869), [PBKDF2](https://tools.ietf.org/html/rfc8018#section-5.2) |
| Key Exchange                | [X25519](https://tools.ietf.org/html/rfc7748), [RSA](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf), [ECDH](https://www.secg.org/sec1-v2.pdf) |
| Hashing                     | [SHA-2 (224/256/384/512)](https://tools.ietf.org/html/rfc4634) |
| Message Authentication Code | [HMAC](https://www.ietf.org/rfc/rfc2104.txt)                 |
| Digital Signature           | [Ed25519](https://tools.ietf.org/html/rfc8032), [RSASSA-PSS](https://tools.ietf.org/html/rfc4056), [ECDSA](https://www.secg.org/sec1-v2.pdf) |
| Entropy Source              | Linux, macOS [/dev/urandom](https://tls.mbed.org/module-level-design-rng),<br>Windows [CryptGenRandom()](https://tls.mbed.org/module-level-design-rng) |
| Symmetric Algorithms        | [AES-256-GCM](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), [AES-256-CBC](https://tools.ietf.org/html/rfc3602) |
| Encryption schemes          | [PBES2](https://tools.ietf.org/html/rfc8018#section-6.2)     |
| Elliptic Curves             | [Ed25519](https://tools.ietf.org/html/rfc8032), [Curve25519](https://tools.ietf.org/html/rfc7748), [secp256R1](https://www.secg.org/sec1-v2.pdf) |

### Library: PHE

The cryptographic background for the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers the technology to protect user passwords from offline attacks and render stolen passwords useless even if your database has been compromised. The service implementation can be found [here](https://github.com/passw0rd/phe-go).

### Library: Pythia

The cryptographic background for the  [Pythia PRF Service](http://pages.cs.wisc.edu/~ace/papers/pythia-full.pdf).

### Library: Ratchet

Implementation of the [Double Ratchet Algorithm](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm).


## Platforms & languages

| Library    | Platforms    | Languages / Binaries                                         |
| ---------- | ------------ | ------------------------------------------------------------ |
| foundation | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [Swift](https://github.com/VirgilSecurity/virgil-cryptowrapper-x), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib) |
| pythia     | linux, macOS | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [Swift](https://github.com/VirgilSecurity/virgil-cryptowrapper-x), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib) |
| phe        | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [PHP](https://cdn.virgilsecurity.com/virgil-crypto-c/php), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib) |
| ratchet    | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [Swift](https://github.com/VirgilSecurity/virgil-cryptowrapper-x), [Java](https://mvnrepository.com/artifact/com.virgilsecurity.crypto), [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript), [Python](https://pypi.org/project/virgil-crypto-lib) |



## Build from sources

### Prerequisites

* Compiler:
  - `gcc` (version >= 4.8.2), or
  - `clang` (version >= 3.6), or
  - `msvc` (version >= 14.0)
* Build tools:
  - `cmake` (version >= 3.11)
  - `python` (version >= 2.7)
  - `python-protobuf`

### Build & Install

```bash
git clone https://github.com/VirgilSecurity/virgil-crypto-c.git
cd virgil-crypto-c
cmake -Bbuild -H.
cmake --build build
cmake --build build --target install
```



## Support

Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

## License

BSD 3-Clause. See [LICENSE](LICENSE) for details.
