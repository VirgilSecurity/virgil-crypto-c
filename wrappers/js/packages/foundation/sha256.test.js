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
      const correctDigest = Buffer.from(
        '3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7',
        'hex',
      );
      expect(digest).toEqual(correctDigest);
      done();
    });
    sha256.write(Buffer.from('d'));
    sha256.write(Buffer.from('a'));
    sha256.write(Buffer.from('t'));
    sha256.write(Buffer.from('a'));
    sha256.end();
  });

  describe('hash', () => {
    it('should return digest', () => {
      const digest = sha256.hash(Buffer.from('data'));
      const correctDigest = Buffer.from(
        '3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7',
        'hex',
      );
      expect(digest).toEqual(correctDigest);
    });
  });
});
