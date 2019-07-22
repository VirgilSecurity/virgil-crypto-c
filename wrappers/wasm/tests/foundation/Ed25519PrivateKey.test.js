const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('Ed25519PrivateKey', () => {
  let foundation;
  let ed25519;
  let keyProvider;

  beforeEach(async () => {
    foundation = await initFoundation();
    ed25519 = new foundation.Ed25519();
    keyProvider = new foundation.KeyProvider();
    ed25519.setupDefaults();
    keyProvider.setupDefaults();
  });

  test('import private key', () => {
    const privateKeyData = hexToUint8Array('302e020100300506032b657004220420f04dd792bc2965f9ecf0b9d0c78190b1224b77680c7ab22b301e7825fa7bab5e');
    const privateKey = keyProvider.importPrivateKey(privateKeyData);
    const len = privateKey.len();
    expect(len).toBe(32);
  });

  test('export private key', () => {
    const privateKeyData = hexToUint8Array('302e020100300506032b657004220420f04dd792bc2965f9ecf0b9d0c78190b1224b77680c7ab22b301e7825fa7bab5e');
    const privateKey = keyProvider.importPrivateKey(privateKeyData);
    const exportedKey = keyProvider.exportPrivateKey(privateKey);
    expect(exportedKey.toString()).toBe(privateKeyData.toString());
  });

  test('extract public key', () => {
    const privateKeyData = hexToUint8Array('302e020100300506032b657004220420f04dd792bc2965f9ecf0b9d0c78190b1224b77680c7ab22b301e7825fa7bab5e');
    const publicKeyData = hexToUint8Array('302a300506032b6570032100d2f4f7c2dc70cf17e0fcc1d23afaec6bd5cc0de9fba179f78896bb2c65abc967');
    const privateKey = keyProvider.importPrivateKey(privateKeyData);
    const publicKey = privateKey.getPublicKey();
    const exportedPublicKey = keyProvider.exportPublicKey(publicKey);
    expect(exportedPublicKey.toString()).toBe(publicKeyData.toString());
  });

  test('sign hash', () => {
    const privateKeyData = hexToUint8Array('302e020100300506032b657004220420f04dd792bc2965f9ecf0b9d0c78190b1224b77680c7ab22b301e7825fa7bab5e');
    const publicKeyData = hexToUint8Array('302a300506032b6570032100d2f4f7c2dc70cf17e0fcc1d23afaec6bd5cc0de9fba179f78896bb2c65abc967');
    const privateKey = keyProvider.importPrivateKey(privateKeyData);
    const publicKey = keyProvider.importPublicKey(publicKeyData);
    const digest = hexToUint8Array('3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7');
    const signer = new foundation.Signer();
    const hash = new foundation.Sha512();
    const fakeRandom = new foundation.FakeRandom();
    fakeRandom.setupSourceByte(0xab);
    signer.hash = hash;
    signer.random = fakeRandom;
    signer.reset();
    signer.appendData(digest);
    const signature = signer.sign(privateKey);
    const expectedSignature = hexToUint8Array('3051300d06096086480165030402030500044042b24411d9615ea71d7613068dc9e94151b1e723fc04eb420e2f848bd7074f3af5344472a2d6aefd7868969f0780ab8d0f4ae2c1d120c204e9d073e3ad4be00e');
    expect(signature.toString()).toBe(expectedSignature.toString());
  });

  test('generate key', () => {
    const fakeRandom = new foundation.FakeRandom();
    const sourceData = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
    fakeRandom.setupSourceData(sourceData);
    ed25519.random = fakeRandom;
    const privateKey = ed25519.generateKey();
    const exportedKey = keyProvider.exportPrivateKey(privateKey);
    const expectedKey = hexToUint8Array('302e020100300506032b6570042204204d43344341514177425159444b32567742434945494573434c484e506358502b');
    expect(exportedKey.toString()).toBe(expectedKey.toString());
  });

  test('encrypt / decrypt', () => {
    const key = hexToUint8Array('302e020100300506032b657004220420cc266dad3d3cd7f8de961f18f351590cdf2313281fd2026f348c97e51ad74a56');
    const privateKey = keyProvider.importPrivateKey(key);
    const publicKey = privateKey.getPublicKey();
    const data = hexToUint8Array('64617461');
    const encrypted = ed25519.encrypt(publicKey, data);
    const decrypted = ed25519.decrypt(privateKey, encrypted);
    expect(decrypted.toString()).toBe(data.toString());
  });
});
