const initFoundation = require('../../foundation');

describe('Sha256', () => {
  let foundation;
  let sha256;

  beforeEach(async () => {
    foundation = await initFoundation();
    sha256 = new foundation.Sha256();
  });

  describe('hash', () => {
    test('1', () => {
      const input = Buffer.alloc(0);
      const result = sha256.hash(input);
      const expectedResult = Buffer.from(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });

    test('2', () => {
      const input = Buffer.from('bd', 'hex');
      const result = sha256.hash(input);
      const expectedResult = Buffer.from(
        '68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });

    test('3', () => {
      const input = Buffer.from('5fd4', 'hex');
      const result = sha256.hash(input);
      const expectedResult = Buffer.from(
        '7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });
  });

  describe('stream', () => {
    test('1', () => {
      const input = Buffer.alloc(0);
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = Buffer.from(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });

    test('2', () => {
      const input = Buffer.from('bd', 'hex');
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = Buffer.from(
        '68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });

    test('3', () => {
      const input = Buffer.from('5fd4', 'hex');
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = Buffer.from(
        '7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788',
        'hex',
      );
      expect(Buffer.compare(expectedResult, result)).toBe(0);
    });
  });
});
