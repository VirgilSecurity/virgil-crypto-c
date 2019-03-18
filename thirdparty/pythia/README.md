# Pythia Library
[![Build Status](https://travis-ci.org/VirgilSecurity/pythia.svg?branch=master)](https://travis-ci.org/VirgilSecurity/pythia)
[![GitHub license](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Dependencies](#dependencies) | [Deterministic RNG](#deterministic-rng)| [Support](#support) | [License](#license)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> Welcome to Virgil Pythia Library! 

**Virgil Pythia** is a C library which implements all required cryptographic functions and primitives to perform an implementation of [Pythia](http://pages.cs.wisc.edu/~ace/papers/pythia-full.pdf), the most **advanced protocol** of protecting passwords and generating keys based on passwords.

Pythia’s originators are: Adam Everspaugh and Rahul Chaterjee, University of
Wisconsin—Madison; Samuel Scott, University of London; Ari Juels and Thomas Ristenpart,
Cornell Tech.

## Library purposes

Pythia Library allows developers to implement Pythia service and client flows using the supplied functions.


## Dependencies

### Libraries

  - Multithread:
      - openmp (optional)
      - pthread (optional)

### Platform dependent features

  - when *TIMER* eqals *CYCLE* (optional)
      - intitialization occurs within function `arch_init()`

  - random number generator
      - `CryptGenRandom` on Windows
      - `/dev/random` on Unix/Linux
      - `/dev/urandom`  on Unix/Linux
      - `libc rand()/random()` is crossplatform (insecure!)
      - `zero seed` is a crossplatform (insecure!)
      - `custom` can be defined on a client side for any platform

## License

This library is released under the [AGPL-3.0 license](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
