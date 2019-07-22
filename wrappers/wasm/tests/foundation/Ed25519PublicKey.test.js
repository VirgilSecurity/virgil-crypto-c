const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('Ed25519PublicKey', () => {
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

  test('key len', () => {
    const privateKey = ed25519.generateKey();
    const publicKey = privateKey.getPublicKey();
    const len = publicKey.len();
    expect(len).toBe(32);
  });

  test('export public key', () => {
    const publicKeyData = hexToUint8Array('302a300506032b6570032100d2f4f7c2dc70cf17e0fcc1d23afaec6bd5cc0de9fba179f78896bb2c65abc967');
    const publicKey = keyProvider.importPublicKey(publicKeyData);
    const exported = keyProvider.exportPublicKey(publicKey);
    expect(exported.toString()).toBe(publicKeyData.toString());
  });

  test('verify hash', () => {
    const publicKeyData = hexToUint8Array('302a300506032b6570032100d2f4f7c2dc70cf17e0fcc1d23afaec6bd5cc0de9fba179f78896bb2c65abc967');
    const digest = hexToUint8Array('3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7');
    const signature = hexToUint8Array('3051300d06096086480165030402030500044042b24411d9615ea71d7613068dc9e94151b1e723fc04eb420e2f848bd7074f3af5344472a2d6aefd7868969f0780ab8d0f4ae2c1d120c204e9d073e3ad4be00e');
    const publicKey = keyProvider.importPublicKey(publicKeyData);
    const verifier = new foundation.Verifier();
    verifier.reset(signature);
    verifier.appendData(digest);
    const result = verifier.verify(publicKey);
    expect(result).toBeTruthy();
  });

  test('encrypt', () => {
    const privateKeyData = hexToUint8Array('302e020100300506032b657004220420f04dd792bc2965f9ecf0b9d0c78190b1224b77680c7ab22b301e7825fa7bab5e');
    const publicKeyData = hexToUint8Array('302a300506032b6570032100d2f4f7c2dc70cf17e0fcc1d23afaec6bd5cc0de9fba179f78896bb2c65abc967');
    const data = hexToUint8Array('64617461');
    const privateKey = keyProvider.importPrivateKey(privateKeyData);
    const publicKey = keyProvider.importPublicKey(publicKeyData);
    const encrypted = ed25519.encrypt(publicKey, data);
    const decrypted = ed25519.decrypt(privateKey, encrypted);
    expect(decrypted.toString()).toBe(data.toString());
  });
});
