/* eslint-env jest */

const Sha256 = require('./sha256');

describe('Sha256', () => {
  let sha256;

  beforeEach(() => {
    sha256 = new Sha256();
  });

  it('should implement a Transform stream', done => {
    sha256.on('readable', () => {
      const digest = sha256.read();
      expect(Buffer.isBuffer(digest)).toBeTruthy();
      done();
    });
    sha256.write(Buffer.from('first'));
    sha256.write(Buffer.from('second'));
    sha256.write(Buffer.from('third'));
    sha256.end();
  });

  describe('hash', () => {
    it('should return digest', () => {
      const digest = sha256.hash(Buffer.from('data'));
      expect(Buffer.isBuffer(digest)).toBeTruthy();
    });
  });
});
