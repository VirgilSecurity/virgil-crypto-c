# virgil-crypto-c ChangeLog (Sorted by date)


## Version 0.11.0 released 2019-10-07

### Bugfix

- Lib/Foundation: Fixed crash when import private key from valid ASN.1 but not a private key

### Features

- Lib/Foundation: Operations "sign then encrypt" and "decrypt then verify" were added to "RecipientCipher" class
- Lib/Foundation: Method "hasKeyRecipient()" was added to class "RecipientCipher"
- Lib/Foundation: Method "preciseEncryptedLen()" was added to interface "Encrypt"

### Changes

- Lib/Foundation: Interface "CipherAuth" now inherit interface "Cipher"
- Lib/Foundation/Wrappers: Listed methods where removed from class "MessageInfo":
  * addKeyRecipient()
  * addPasswordRecipient()
  * setDataEncryptionAlgInfo()
  * setCustomParams()
  * clearRecipients()
- Lib/Foundation/Wrappers: Method "add()" was removed from class "KeyRecipientInfoList"
- Lib/Foundation/Wrappers: Method "add()" was removed from class "PasswordRecipientInfoList"


## Version 0.10.3 released 2019-09-10

### Changes

- Lib/Foundation: Added method "unlock" to the class MessageInfoEditor


## Version 0.10.2 released 2019-09-09

### Features

- Lib/Foundation: Added support for managing recipients within MessageInfo
- Lib/PHE: Added PHE Cipher additional data support

### Changes

- Wrapper/Java: Run java benchmark with a profile only


## Version 0.10.1 released 2019-09-02

### Bugfix

- Lib/Foundation: Fix crash when export secp256r1 private key with leading zero
- Wrapper/Swift: Fix memory leaks
- Wrapper/Java: Fix memory leaks


## Version 0.10.0 released 2019-08-12

### Changes

- Lib/Foundation/Ratchet: Fix group chat encryption

### Bugfix

- Wrapper/Python: Fix Python 2.7 package name for macOS platform
- Wrapper/JS: Fix npm packages


## Version 0.9.0 released 2019-08-06

### Bugfix

- Lib/Foundation: Fix crash when import secp256r1 public key

### Features

- Wrapper/JS: Add wrapper for JavaScript (Beta)
- Wrapper/Python: Add wrapper for Python (Beta)


## Version 0.8.1 released 2019-07-08

### Changes

- Lib/Foundation: Fixed group session API


## Version 0.8.0 released 2019-07-04

### Features

- Lib/Foundation: Added group session encryption based on symmetric key sharing
- Lib/Ratchet: Small improvements

### Changes

- Lib/Foundation: Split asymmetric keys and their algorithms to different entities

### Bugfix

- Lib/Foundation: Fix crashes in a multi-thread environment


## Version 0.7.1 released 2019-06-03

### Bugfix

- Lib/Foundation: Fix asn1 key deserializer - return status code when passing an invalid key instead of failing on assertion
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

- All: Add constant-time memory, data and buffer comparisons
- Foundation: Add the ability to export keys to the PKCS#8 format with the class "Key Provider"
- Foundation: Add umbrella headers
- Ratchet: Add group chats

### Changes

- Foundation: Remove the ability to specify the RSA public exponent for key generation


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

- PHE: Added the class "PHE Cipher"


## Version 0.1.0 released 2018-12-20

This is an initial unstable pre-release version of the library.
The API can be changed without any backward compatibilities.
