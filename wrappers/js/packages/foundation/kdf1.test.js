/* eslint-env jest */

const Kdf1 = require('./kdf1');
const Sha256 = require('./sha256');

describe('Kdf1', () => {
  let kdf1;

  beforeEach(() => {
    const sha256 = new Sha256();
    kdf1 = new Kdf1(sha256);
  });

  describe('useHash', () => {
    it('should work', () => {
      const sha256 = new Sha256();
      const result = kdf1.useHash(sha256);
      expect(result).toBeUndefined();
    });
  });

  describe('derive', () => {
    it('should return key of the requested length from the given data', () => {
      const data = Buffer.from('data');
      const keyLength = 3;
      const key = kdf1.derive(data, keyLength);
      expect(Buffer.isBuffer(key)).toBeTruthy();
    });
  });
});
