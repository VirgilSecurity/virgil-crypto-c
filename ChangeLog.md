# virgil-crypto-c ChangeLog (Sorted per date)


## Version 0.7.1 released 2019-06-03

### Bugfix

- Lib/Foundation: Fix asn1 key deserializer - return status code when pass invalid key instead of fail on assertion
- Lib/Foundation: Fix chunk encryption/decryption for AES256-GCM


## Version 0.7.0 released 2019-05-14

### Features

- Lib/Foundation: Add elliptic curve secp256r1 (NIST P-256)
- Lib/Ratchet: Add group chats
- Wrapper/Java: Add Java wrapper
- Wrapper/PHP: Add version 7.3

### Changes

- Lib/Foundation: Export ed25519 and curve25519 private key as is - 32 bytes
- Lib/Foundation: Rename class "pkcs8 der deserializer" -> "asn1 deserializer"
- Lib/Foundation: Rename class "pkcs8 der serializer" -> "pkcs8 serializer"
- Lib/Foundation: Rename class "pkcs8 deserializer" -> "asn1 deserializer"

### Bugfix

- Lib/Foundation: Fix SIGSEGV at messageInfoCustomParams_findData method
- Lib/Foundation: Fix aes_256_gcm_auth_len() function


## Version 0.6.0 released 2019-04-09

### Features

- All: Add constant-time memory, data and buffer comparison
- Foundation: Add ability to export keys to the PKCS#8 format with a class "Key Provider"
- Foundation: Add umbrella headers
- Ratchet: Add group chats

### Changes

- Foundation: Remove ability to specify RSA public exponent for key generation


## Version 0.5.0 released 2019-03-20

### Features

- Add algorithm AES-256-CBC
- Add algorithm PKCS#5 PBES2
- Add algorithm PKCS#5 PBKDF2
- Add algorithm ECIES
- Add elliptic curve: curve25519
- Add algorithm serialization / deserialization (DER format)
- Add high-level class "recipient cipher" for simple encryption / decryption
- Add high-level class "signer" for simple sign / verify
- Add CocoaPods and Carthage spec files

### Bugfix

- Fix wrapper generation for Swift
- Fix ed25519 elliptic curve


## Version 0.2.0 released 2019-01-09

### Features

- PHE: Added class "PHE Cipher"


## Version 0.1.0 released 2018-12-20

This is initial unstable pre-release version of the library.
API can be changed without any backward compatibilities.
