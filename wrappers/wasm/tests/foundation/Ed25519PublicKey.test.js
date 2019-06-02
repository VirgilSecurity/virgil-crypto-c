const initFoundation = require('../../foundation');

describe('Ed25519PublicKey', () => {
  let foundation;
  let ed25519PublicKey;

  beforeEach(async () => {
    foundation = await initFoundation();
    ed25519PublicKey = new foundation.Ed25519PublicKey();
    ed25519PublicKey.setupDefaults();
  });

  describe('keyLen', () => {
    it('should work', () => {
      const key = Buffer.from(
        'e7349dd5eb23233766f3192e2d9d4d26d8a2671d71e8aed48053b47f55f47032',
        'hex',
      );
      ed25519PublicKey.importPublicKey(key);
      const len = ed25519PublicKey.keyLen();
      expect(len).toBe(32);
    });
  });

  describe('exportPublicKey', () => {
    it('should work', () => {
      const key = Buffer.from(
        'e7349dd5eb23233766f3192e2d9d4d26d8a2671d71e8aed48053b47f55f47032',
        'hex',
      );
      ed25519PublicKey.importPublicKey(key);
      const result = ed25519PublicKey.exportPublicKey();
      expect(Buffer.compare(result, key)).toBe(0);
    });
  });

  describe('verifyHash', () => {
    it('should work', () => {
      const key = Buffer.from(
        'e7349dd5eb23233766f3192e2d9d4d26d8a2671d71e8aed48053b47f55f47032',
        'hex',
      );
      ed25519PublicKey.importPublicKey(key);
      const digest = Buffer.from(
        '3684a316a74ab39bd2c29a2e862f05795be949b212c920c43d21d4ce9d41016a',
        'hex',
      );
      const signature = Buffer.from(
        'f22bd5b9648c906b1951deed256ce295114b0b699a068fc52c156b4ff3efa5ae035e48f447e9e21f6d6339e5508f6b273271f76fc90df95c0e965436482e1402',
        'hex',
      );
      const result = ed25519PublicKey.verifyHash(digest, foundation.AlgId.SHA256, signature);
      expect(result).toBeTruthy();
    });
  });

  describe('encrypt', () => {
    it('should work', () => {
      const key = Buffer.from(
        'e7349dd5eb23233766f3192e2d9d4d26d8a2671d71e8aed48053b47f55f47032',
        'hex',
      );
      ed25519PublicKey.importPublicKey(key);
      const data = Buffer.from(
        '3237643230393430656630363034643232396332346535613565623230623136',
        'hex',
      );
      const result = ed25519PublicKey.encrypt(data);
      expect(result).toBeInstanceOf(Uint8Array);
    });
  });
});
