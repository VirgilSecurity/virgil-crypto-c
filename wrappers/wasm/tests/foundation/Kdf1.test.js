const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('Kdf1', () => {
  let foundation;
  let kdf1;
  let sha256;

  beforeEach(async () => {
    foundation = await initFoundation();
    kdf1 = new foundation.Kdf1();
    sha256 = new foundation.Sha256();
    kdf1.hash = sha256;
  });

  afterEach(() => {
    kdf1.delete();
    sha256.delete();
  });

  describe('derive', () => {
    test('1', () => {
      const data = new Uint8Array();
      const key = hexToUint8Array('df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119b40711a88c703975');
      const result = kdf1.derive(data, key.length);
      expect(result.toString()).toBe(key.toString());
    });

    test('2', () => {
      const data = hexToUint8Array('bd');
      const key = hexToUint8Array('a759b860b37fe77847406f266b7d7f1e838d814addf2716ecf4d824dc8b56f71823bfae3b6e7cd29');
      const result = kdf1.derive(data, key.length);
      expect(result.toString()).toBe(key.toString());
    });

    test('3', () => {
      const data = hexToUint8Array('5fd4');
      const key = hexToUint8Array('c6067722ee5661131d53437e649ed1220858f88164819bb867d6478714f8f3c8002422afdd96bf48');
      const result = kdf1.derive(data, key.length);
      expect(result.toString()).toBe(key.toString());
    });
  });
});
