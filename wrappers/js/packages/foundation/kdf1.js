const { Kdf1: Kdf1Binding } = require('bindings')('foundation');

class Kdf1 {
  constructor(hash) {
    this.binding = new Kdf1Binding(hash.binding);
  }

  useHash(hash) {
    this.binding.useHash(hash.binding);
  }

  derive(data, keyLength) {
    return this.binding.derive(data, keyLength);
  }
}

module.exports = Kdf1;
