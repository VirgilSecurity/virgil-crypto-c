const initFoundation = require('../../foundation');
const { hexToUint8Array } = require('../utils');

describe('Ed25519PrivateKey', () => {
  let foundation;
  let ed25519PrivateKey;

  beforeEach(async () => {
    foundation = await initFoundation();
    ed25519PrivateKey = new foundation.Ed25519PrivateKey();
    ed25519PrivateKey.setupDefaults();
  });

  describe('importPrivateKey', () => {
    it('should work', () => {
      const privateKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      ed25519PrivateKey.importPrivateKey(privateKey);
      const keyLen = ed25519PrivateKey.keyLen();
      expect(keyLen).toBe(32);
    });
  });

  describe('exportPrivateKey', () => {
    it('should work', () => {
      const privateKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      ed25519PrivateKey.importPrivateKey(privateKey);
      const exportedKey = ed25519PrivateKey.exportPrivateKey();
      expect(exportedKey.toString()).toBe(privateKey.toString());
    });
  });

  describe('extractPublicKey', () => {
    it('should work', () => {
      const privateKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      ed25519PrivateKey.importPrivateKey(privateKey);
      const publicKey = ed25519PrivateKey.extractPublicKey();
      expect(publicKey).toBeInstanceOf(foundation.Ed25519PublicKey);
    });
  });

  describe('signHash', () => {
    it('should work', () => {
      const privateKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      ed25519PrivateKey.importPrivateKey(privateKey);
      const digest = hexToUint8Array('3684a316a74ab39bd2c29a2e862f05795be949b212c920c43d21d4ce9d41016a');
      const signature = ed25519PrivateKey.signHash(digest, foundation.AlgId.SHA256);
      const expectedSignature = hexToUint8Array('f22bd5b9648c906b1951deed256ce295114b0b699a068fc52c156b4ff3efa5ae035e48f447e9e21f6d6339e5508f6b273271f76fc90df95c0e965436482e1402');
      expect(signature.toString()).toBe(expectedSignature.toString());
    });
  });

  describe('generateKey', () => {
    it('should work', () => {
      const fakeRandom = new foundation.FakeRandom();
      const sourceData = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      fakeRandom.setupSourceData(sourceData);
      ed25519PrivateKey.random = fakeRandom;
      ed25519PrivateKey.generateKey();
      const exportedKey = ed25519PrivateKey.exportPrivateKey();
      const expectedKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      expect(exportedKey.toString()).toBe(expectedKey.toString());
    });
  });

  describe('decrypt', () => {
    it('should work', () => {
      const privateKey = hexToUint8Array('4d43344341514177425159444b32567742434945494573434c484e506358502b');
      ed25519PrivateKey.importPrivateKey(privateKey);
      const encryptedData = hexToUint8Array('3081db020100302a300506032b6570032100854f7797283006ae5e474dfb612c41cbdbd17cd3d31b2160211e6b66d88712a43016060728818c71020502300b0609608648016503040202303f300b06096086480165030402020430a7a6b8ef584c2b419d7a43a88abaa6565ef633b280e8ef3ba61975f536164650965426f4c7cc8b3e842175e1ea1319533051301d060960864801650304012a041028c8a5d13a37ef6c9a0a35ab9427fb0f04306440c128087ed091ef380ee3d4b832c66293700ea965dddd254d18830268548e09d24cfa08f4015864e2eee1cf0b3477');
      const decrypedData = ed25519PrivateKey.decrypt(encryptedData);
      const expectedData = hexToUint8Array('3237643230393430656630363034643232396332346535613565623230623136');
      expect(decrypedData.toString()).toBe(expectedData.toString());
    });
  });
});
