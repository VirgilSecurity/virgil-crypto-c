const initSha256 = emscriptenModule => {
  class Sha256 {
    static get DIGEST_LEN() {
      return 32;
    }

    static get BLOCK_LEN() {
      return 64;
    }

    constructor() {
      this.ctxPtr = emscriptenModule._vscf_sha256_new();
    }

    free() {
      this.throwUnlessHasContext();
      emscriptenModule._vscf_sha256_delete(this.ctxPtr);
      this.ctxPtr = undefined;
    }

    static hash(data) {
      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = emscriptenModule.HEAP8.buffer;

      const dataSize = data.length * data.BYTES_PER_ELEMENT;
      const dataPtr = emscriptenModule._malloc(dataSize);
      emscriptenModule.HEAP8.set(data, dataPtr);

      const dataCtxSize = emscriptenModule._vsc_data_ctx_size();
      const dataCtxPtr = emscriptenModule._malloc(dataCtxSize);

      const dataCtxHeap = new Uint32Array(buffer, dataCtxPtr, dataCtxSize);
      dataCtxHeap[0] = dataPtr;
      dataCtxHeap[1] = dataSize;

      const bufferSize = Sha256.DIGEST_LEN;
      const bufferPtr = emscriptenModule._vsc_buffer_new_with_capacity(bufferSize);

      emscriptenModule._vscf_sha256_hash(dataCtxPtr, bufferPtr);

      const bytesPtr = emscriptenModule._vsc_buffer_bytes(bufferPtr);
      const result = new Uint8Array(buffer, bytesPtr, bufferSize).slice();

      // If C structure is returned by value, then WASM expects
      // a pointer to this structure as a first parameter.
      // emscriptenModule._vsc_buffer_data(cdataPtr, outputPtr);
      // console.log(data2hex(new Uint8Array(buffer, emscriptenModule._vsc_data_bytes(cdataPtr), emscriptenModule._vsc_data_len(cdataPtr))));

      emscriptenModule._free(dataPtr);
      emscriptenModule._free(dataCtxPtr);
      emscriptenModule._vsc_buffer_delete(bufferPtr);

      return result;
    }

    start() {
      this.throwUnlessHasContext();
      emscriptenModule._vscf_sha256_start(this.ctxPtr);
    }

    update(data) {
      this.throwUnlessHasContext();

      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = emscriptenModule.HEAP8.buffer;

      const dataSize = data.length * data.BYTES_PER_ELEMENT;
      const dataPtr = emscriptenModule._malloc(dataSize);
      emscriptenModule.HEAP8.set(data, dataPtr);

      const dataCtxSize = emscriptenModule._vsc_data_ctx_size();
      const dataCtxPtr = emscriptenModule._malloc(dataCtxSize);

      const dataCtxHeap = new Uint32Array(buffer, dataCtxPtr, dataCtxSize);
      dataCtxHeap[0] = dataPtr;
      dataCtxHeap[1] = dataSize;

      emscriptenModule._vscf_sha256_update(this.ctxPtr, dataCtxPtr);

      emscriptenModule._free(dataCtxPtr);
    }

    finish() {
      this.throwUnlessHasContext();

      // TODO: Maybe there is an elegant way to access the memory...
      const buffer = emscriptenModule.HEAP8.buffer;

      const bufferSize = Sha256.DIGEST_LEN;
      const bufferPtr = emscriptenModule._vsc_buffer_new_with_capacity(bufferSize);

      emscriptenModule._vscf_sha256_finish(this.ctxPtr, bufferPtr);

      const bytesPtr = emscriptenModule._vsc_buffer_bytes(bufferPtr);
      const result = new Uint8Array(buffer, bytesPtr, bufferSize).slice();

      emscriptenModule._vsc_buffer_delete(bufferPtr);

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
