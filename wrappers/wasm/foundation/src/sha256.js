const initSha256 = Module => {
  class Sha256 {
    static get DIGEST_LEN() {
      return 32;
    }

    static get BLOCK_LEN() {
      return 64;
    }

    constructor() {
      this.ctxPtr = Module._vscf_sha256_new();
    }

    free() {
      this.throwUnlessHasContext();
      Module._vscf_sha256_delete(this.ctxPtr);
      this.ctxPtr = undefined;
    }

    static hash(data) {
      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = Module.HEAP8.buffer;

      const dataSize = data.length * data.BYTES_PER_ELEMENT;
      const dataPtr = Module._malloc(dataSize);
      Module.HEAP8.set(data, dataPtr);

      const dataCtxSize = Module._vsc_data_ctx_size();
      const dataCtxPtr = Module._malloc(dataCtxSize);

      const dataCtxHeap = new Uint32Array(buffer, dataCtxPtr, dataCtxSize);
      dataCtxHeap[0] = dataPtr;
      dataCtxHeap[1] = dataSize;

      const bufferSize = Sha256.DIGEST_LEN;
      const bufferPtr = Module._vsc_buffer_new_with_capacity(bufferSize);

      Module._vscf_sha256_hash(dataCtxPtr, bufferPtr);

      const bytesPtr = Module._vsc_buffer_bytes(bufferPtr);
      const result = new Uint8Array(buffer, bytesPtr, bufferSize).slice();

      // If C structure is returned by value, then WASM expects
      // a pointer to this structure as a first parameter.
      // Module._vsc_buffer_data(cdataPtr, outputPtr);
      // console.log(data2hex(new Uint8Array(buffer, Module._vsc_data_bytes(cdataPtr), Module._vsc_data_len(cdataPtr))));

      Module._free(dataPtr);
      Module._free(dataCtxPtr);
      Module._vsc_buffer_delete(bufferPtr);

      return result;
    }

    start() {
      this.throwUnlessHasContext();
      Module._vscf_sha256_start(this.ctxPtr);
    }

    update(data) {
      this.throwUnlessHasContext();

      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = Module.HEAP8.buffer;

      const dataSize = data.length * data.BYTES_PER_ELEMENT;
      const dataPtr = Module._malloc(dataSize);
      Module.HEAP8.set(data, dataPtr);

      const dataCtxSize = Module._vsc_data_ctx_size();
      const dataCtxPtr = Module._malloc(dataCtxSize);

      const dataCtxHeap = new Uint32Array(buffer, dataCtxPtr, dataCtxSize);
      dataCtxHeap[0] = dataPtr;
      dataCtxHeap[1] = dataSize;

      Module._vscf_sha256_update(this.ctxPtr, dataCtxPtr);

      Module._free(dataCtxPtr);
    }

    finish() {
      this.throwUnlessHasContext();

      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = Module.HEAP8.buffer;

      const bufferSize = Sha256.DIGEST_LEN;
      const bufferPtr = Module._vsc_buffer_new_with_capacity(bufferSize);

      Module._vscf_sha256_finish(this.ctxPtr, bufferPtr);

      const bytesPtr = Module._vsc_buffer_bytes(bufferPtr);
      const result = new Uint8Array(buffer, bytesPtr, bufferSize).slice();

      Module._vsc_buffer_delete(bufferPtr);

      return result;
    }

    throwUnlessHasContext() {
      if (typeof this.ctxPtr === 'undefined') {
        throw new Error('The instance does not have a context');
      }
    }
  }

  return Sha256;
}

module.exports = initSha256;
