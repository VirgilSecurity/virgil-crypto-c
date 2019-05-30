/**
 * Copyright (C) 2015-2019 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * (1) Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * (3) Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */


const initPkcs5Pbes2 = (Module, modules) => {
    /**
     * Virgil Security implementation of the PBES2 (RFC 8018) algorithm.
     */
    class Pkcs5Pbes2 {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Pkcs5Pbes2';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_pkcs5_pbes2_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        /**
         * Acquire C context by making it's shallow copy.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Pkcs5Pbes2(Module._vscf_pkcs5_pbes2_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Pkcs5Pbes2(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_pkcs5_pbes2_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set kdf(kdf) {
            Module._vscf_pkcs5_pbes2_release_kdf(this.ctxPtr)
            Module._vscf_pkcs5_pbes2_use_kdf(this.ctxPtr, kdf.ctxPtr)
        }

        set cipher(cipher) {
            Module._vscf_pkcs5_pbes2_release_cipher(this.ctxPtr)
            Module._vscf_pkcs5_pbes2_use_cipher(this.ctxPtr, cipher.ctxPtr)
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbes2_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Produce object with algorithm information and configuration parameters.
         */
        produceAlgInfo() {
            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbes2_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Restore algorithm configuration from the given object.
         */
        restoreAlgInfo(algInfo) {
            const proxyResult = Module._vscf_pkcs5_pbes2_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Encrypt given data.
         */
        encrypt(data) {
            // assert(typeof data === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.encryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_pkcs5_pbes2_encrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Calculate required buffer length to hold the encrypted data.
         */
        encryptedLen(dataLen) {
            // assert(typeof dataLen === 'number')

            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbes2_encrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Decrypt given data.
         */
        decrypt(data) {
            // assert(typeof data === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.decryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_pkcs5_pbes2_decrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Calculate required buffer length to hold the decrypted data.
         */
        decryptedLen(dataLen) {
            // assert(typeof dataLen === 'number')

            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbes2_decrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Configure cipher with a new password.
         */
        reset(pwd) {
            // assert(typeof pwd === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const pwdSize = pwd.length * pwd.BYTES_PER_ELEMENT;
            const pwdPtr = Module._malloc(pwdSize);
            Module.HEAP8.set(pwd, pwdPtr);

            //  Create C structure vsc_data_t.
            const pwdCtxSize = Module._vsc_data_ctx_size();
            const pwdCtxPtr = Module._malloc(pwdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(pwdCtxPtr, pwdPtr, pwdSize);

            try {
                Module._vscf_pkcs5_pbes2_reset(this.ctxPtr, pwdCtxPtr);
            } finally {
                Module._free(pwdPtr);
                Module._free(pwdCtxPtr);
            }
        }
    }

    return Pkcs5Pbes2;
};

module.exports = initPkcs5Pbes2;
