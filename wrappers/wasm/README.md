# @virgilsecurity/virgil-crypto-core

WebAssembly wrapper for [Virgil Security Crypto C](https://github.com/VirgilSecurity/virgil-crypto-c).

Provides three modules:

| Module | Import path | Contents |
|--------|------------|---------|
| **Foundation** | `@virgilsecurity/virgil-crypto-core/foundation` | Symmetric/asymmetric encryption, signing, hashing, key management, group sessions |
| **PHE** | `@virgilsecurity/virgil-crypto-core/phe` | Password-hardened encryption (PHE) and UOKMS |
| **Ratchet** | `@virgilsecurity/virgil-crypto-core/ratchet` | Double-ratchet end-to-end encrypted sessions |

## Installation

```bash
npm install @virgilsecurity/virgil-crypto-core
```

## Usage

Each module is initialized asynchronously (WASM loads once, then all classes are available synchronously).

### Hashing

```js
const initFoundation = require('@virgilsecurity/virgil-crypto-core/foundation');

const foundation = await initFoundation();
const sha256 = new foundation.Sha256();

const data = Buffer.from('hello world');
const digest = sha256.hash(data);

sha256.delete();
```

### Key generation and encryption

```js
const initFoundation = require('@virgilsecurity/virgil-crypto-core/foundation');

const foundation = await initFoundation();

// Generate Ed25519 key pair
const ed25519 = new foundation.Ed25519();
ed25519.setupDefaults();
const privateKey = ed25519.generateKey();
const publicKey = privateKey.getPublicKey();

// Encrypt
const recipientId = Buffer.from('alice');
const cipher = new foundation.RecipientCipher();
cipher.addKeyRecipient(recipientId, publicKey);
cipher.startEncryption();
const messageInfo = cipher.packMessageInfo();
const ciphertext = Buffer.concat([
    messageInfo,
    cipher.processEncryption(Buffer.from('secret message')),
    cipher.finishEncryption(),
]);

// Decrypt
cipher.startDecryptionWithKey(recipientId, privateKey, new Uint8Array());
const plaintext = Buffer.concat([
    cipher.processDecryption(ciphertext),
    cipher.finishDecryption(),
]);

// Free WASM memory explicitly
cipher.delete();
ed25519.delete();
privateKey.delete();
publicKey.delete();
```

### Signing and verification

```js
const initFoundation = require('@virgilsecurity/virgil-crypto-core/foundation');

const foundation = await initFoundation();

const ed25519 = new foundation.Ed25519();
ed25519.setupDefaults();
const privateKey = ed25519.generateKey();
const publicKey = privateKey.getPublicKey();

const signer = new foundation.Signer();
signer.reset();
signer.appendData(Buffer.from('message'));
const signature = signer.sign(privateKey);

const verifier = new foundation.Verifier();
verifier.reset(signature);
verifier.appendData(Buffer.from('message'));
const valid = verifier.verify(publicKey);  // true

signer.delete();
verifier.delete();
privateKey.delete();
publicKey.delete();
```

### PHE (Password-Hardened Encryption)

```js
const initPhe = require('@virgilsecurity/virgil-crypto-core/phe');

const phe = await initPhe();

const pheServer = new phe.PheServer();
const pheClient = new phe.PheClient();
pheServer.setupDefaults();
pheClient.setupDefaults();

const serverKeyPair = pheServer.generateServerKeyPair();
pheClient.setKeys(clientKeyPair.clientPrivateKey, serverKeyPair.serverPublicKey);

const enrollment = pheServer.getEnrollment(
    serverKeyPair.serverPrivateKey,
    serverKeyPair.serverPublicKey,
);
const { enrollmentRecord, accountKey } = pheClient.enrollAccount(enrollment, Buffer.from('password'));

pheServer.delete();
pheClient.delete();
```

### Ratchet (double-ratchet E2EE session)

```js
const initRatchet = require('@virgilsecurity/virgil-crypto-core/ratchet');

const ratchet = await initRatchet();

const aliceSession = new ratchet.RatchetSession();
const bobSession = new ratchet.RatchetSession();

// ... initialize sessions with key exchange, then:
const message = aliceSession.encrypt(Buffer.from('hello bob'));
const decrypted = bobSession.decryptMessage(message);

aliceSession.delete();
bobSession.delete();
```

## Platform variants

Each module ships three environment builds. Pick the right import path for your target:

| Environment | Import path suffix | Format |
|------------|-------------------|--------|
| Node.js (default) | `@virgilsecurity/virgil-crypto-core/foundation` | CJS / ESM |
| Browser | `@virgilsecurity/virgil-crypto-core/foundation/browser` | ESM |
| Web Worker | `@virgilsecurity/virgil-crypto-core/foundation/worker` | ESM |

Replace `foundation` with `phe` or `ratchet` for the other modules.

## Memory management

WASM objects are not garbage collected. Call `.delete()` on every object when done to release
WASM heap memory. Failing to do so causes memory leaks in long-lived processes.

## Build from source

**Prerequisites:** [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) ≥ 3.1 and CMake ≥ 3.16.

```bash
# 1. Configure and build WASM libraries via CMake (from repo root)
emcmake cmake -DCMAKE_BUILD_TYPE=Release -Bbuild-wasm -S. \
    -DVIRGIL_LIB_PYTHIA=OFF
cmake --build build-wasm -j$(nproc)

# 2. Install npm dependencies
cd wrappers/wasm
npm install

# 3. Bundle with Rollup (builds all three modules into dist/)
npm run prepare
```

## Testing

Tests require the built `dist/` bundles (run `npm run prepare` first).

```bash
cd wrappers/wasm
npm test
```

## License

BSD 3-Clause — see [LICENSE](../../LICENSE).
