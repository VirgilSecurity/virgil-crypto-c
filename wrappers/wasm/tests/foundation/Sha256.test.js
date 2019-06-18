const initFoundation = require('../../dist/foundation/node.cjs');
const { hexToUint8Array } = require('../utils');

describe('Sha256', () => {
  let foundation;
  let sha256;

  beforeEach(async () => {
    foundation = await initFoundation();
    sha256 = new foundation.Sha256();
  });

  describe('hash', () => {
    test('1', () => {
      const input = new Uint8Array();
      const result = sha256.hash(input);
      const expectedResult = hexToUint8Array('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(result.toString()).toBe(expectedResult.toString());
    });

    test('2', () => {
      const input = hexToUint8Array('bd');
      const result = sha256.hash(input);
      const expectedResult = hexToUint8Array('68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b');
      expect(result.toString()).toBe(expectedResult.toString());
    });

    test('3', () => {
      const input = hexToUint8Array('5fd4');
      const result = sha256.hash(input);
      const expectedResult = hexToUint8Array('7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788');
      expect(result.toString()).toBe(expectedResult.toString());
    });
  });

  describe('stream', () => {
    test('1', () => {
      const input = new Uint8Array();
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = hexToUint8Array('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(result.toString()).toBe(expectedResult.toString());
    });

    test('2', () => {
      const input = hexToUint8Array('bd');
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = hexToUint8Array('68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b');
      expect(result.toString()).toBe(expectedResult.toString());
    });

    test('3', () => {
      const input = hexToUint8Array('5fd4');
      sha256.start();
      sha256.update(input);
      const result = sha256.finish();
      const expectedResult = hexToUint8Array('7c4fbf484498d21b487b9d61de8914b2eadaf2698712936d47c3ada2558f6788');
      expect(result.toString()).toBe(expectedResult.toString());
    });
  });
});
