const initFoundation = require('../../foundation');

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

  describe('derive', () => {
    test('1', () => {
      const data = Buffer.alloc(0);
      const key = Buffer.from(
        'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119b40711a88c703975',
        'hex',
      );
      const result = kdf1.derive(data, key.length);
      expect(Buffer.compare(result, key)).toBe(0);
    });

    test('2', () => {
      const data = Buffer.from('bd', 'hex');
      const key = Buffer.from(
        'a759b860b37fe77847406f266b7d7f1e838d814addf2716ecf4d824dc8b56f71823bfae3b6e7cd29',
        'hex',
      );
      const result = kdf1.derive(data, key.length);
      expect(Buffer.compare(result, key)).toBe(0);
    });

    test('3', () => {
      const data = Buffer.from('5fd4', 'hex');
      const key = Buffer.from(
        'c6067722ee5661131d53437e649ed1220858f88164819bb867d6478714f8f3c8002422afdd96bf48',
        'hex',
      );
      const result = kdf1.derive(data, key.length);
      expect(Buffer.compare(result, key)).toBe(0);
    });
  });
});
