[![License](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)

# Virgil Security Crypto Library for C

| branch  | build                                                                                                                                            |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| master  | [![Build Status](https://travis-ci.com/VirgilSecurity/virgil-crypto-c.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-c)  |
| develop | [![Build Status](https://travis-ci.com/VirgilSecurity/virgil-crypto-c.svg?branch=develop)](https://travis-ci.com/VirgilSecurity/virgil-crypto-c) |


## Introduction

This library is designed to be a small, flexible and convenient wrapper for a variety of crypto algorithms.
So it can be used in a small microcontroller as well as in a high load server application. Also, it provides a bunch of custom hybrid algorithms that combine different crypto algorithms to solve common complex cryptographic problems in an easy way. That eliminates requirement for developers to have a strong cryptographic skills.

The library is available for different platforms and contains wrappers for other languages.

## Features

Virgil Security Crypto C library is decomposed to small libraries with specific purposes, so a developer can freely choose a subset of them.

### Library: foundation

This library contains basic cryptographic algorithms and can be used as building blocks for complex solutions.

| Algorithm Purpose    | Implementation details                                       |
| -------------------- | ------------------------------------------------------------ |
| Key Generation, PRNG | CTR_DRBG [NIST SP 800-90A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf) |
| Key Derivation       | [KDF1, KDF2](https://www.shoup.net/iso/std6.pdf),  [HKDF](https://tools.ietf.org/html/rfc5869) |
| Key Exchange         | [X25519](https://tools.ietf.org/html/rfc7748), [RSA](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf) |
| Hashing              | [SHA-2 (224/256/384/512)](https://tools.ietf.org/html/rfc4634) |
| Digital Signature    | [Ed25519](https://tools.ietf.org/html/rfc8032), [RSASSA-PSS](https://tools.ietf.org/html/rfc4056) |
| Entropy Source       | Linux, macOS [/dev/urandom](https://tls.mbed.org/module-level-design-rng),<br>Windows [CryptGenRandom()](https://tls.mbed.org/module-level-design-rng) |
| Symmetric Algorithms | [AES-256-GCM](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) |
| Elliptic Curves      | [Ed25519](https://tools.ietf.org/html/rfc8032)               |

### Library: PHE

Cryptographic background for the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers with a technology to protect users passwords from offline attacks and make stolen passwords useless even if your database has been compromised. Service implementation can be found [here](https://github.com/passw0rd/phe-go).

### Library: Pythia

Cryptographic background for the  [Pythia PRF Service](http://pages.cs.wisc.edu/~ace/papers/pythia-full.pdf).



## Platforms & languages

| Library    | Platforms    | Languages / Binaries                                         |
| ---------- | ------------ | ------------------------------------------------------------ |
| foundation | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c)        |
| pythia     | linux, macOS | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c)        |
| phe        | all          | [C](https://cdn.virgilsecurity.com/virgil-crypto-c/c), [PHP](https://cdn.virgilsecurity.com/virgil-crypto-c/php) |



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

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

## License

BSD 3-Clause. See [LICENSE](LICENSE) for details.
