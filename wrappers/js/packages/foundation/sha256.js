const { Sha256: Sha256Binding } = require('bindings')('foundation');
const { Transform } = require('readable-stream');

class Sha256 extends Transform {
  constructor() {
    super();
    this.binding = new Sha256Binding();
    this.streamRunning = false;
  }

  hash(data) {
    return this.binding.hash(data);
  }

  _transform(chunk, encoding, callback) {
    if (!this.streamRunning) {
      this.streamRunning = true;
      this.binding.start();
    }
    this.binding.update(chunk);
    callback(null);
  }

  _flush(callback) {
    this.streamRunning = false;
    this.push(this.binding.finish());
    callback(null);
  }
}

module.exports = Sha256;
