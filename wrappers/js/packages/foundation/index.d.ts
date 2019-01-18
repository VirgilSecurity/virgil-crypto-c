declare module '@virgilsecurity/foundation' {
  import { Transform } from 'stream';

  interface Kdf {
    useHash(hash: Hash): void;
    derive(data: Buffer, keyLength: Number): Buffer;
  }

  class Kdf1 implements Kdf {
    constructor(hash: Hash);
    useHash(hash: Hash): void;
    derive(data: Buffer, keyLength: Number): Buffer;
  }

  interface Hash {
    hash(data: Buffer): Buffer;
  }

  class Sha256 extends Transform implements Hash {
    hash(data: Buffer): Buffer;
  }
}
