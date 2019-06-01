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


const precondition = require('./precondition');

const initEcies = (Module, modules) => {
    /**
     * Virgil implementation of the ECIES algorithm.
     */
    class Ecies {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Ecies';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_ecies_new();
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
            return new Ecies(Module._vscf_ecies_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Ecies(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_ecies_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            Module._vscf_ecies_release_random(this.ctxPtr)
            Module._vscf_ecies_use_random(this.ctxPtr, random.ctxPtr)
        }

        set cipher(cipher) {
            Module._vscf_ecies_release_cipher(this.ctxPtr)
            Module._vscf_ecies_use_cipher(this.ctxPtr, cipher.ctxPtr)
        }

        set mac(mac) {
            Module._vscf_ecies_release_mac(this.ctxPtr)
            Module._vscf_ecies_use_mac(this.ctxPtr, mac.ctxPtr)
        }

        set kdf(kdf) {
            Module._vscf_ecies_release_kdf(this.ctxPtr)
            Module._vscf_ecies_use_kdf(this.ctxPtr, kdf.ctxPtr)
        }

        /**
         * Set public key that is used for data encryption.
         *
         * If ephemeral key is not defined, then Public Key, must be conformed
         * to the interface "generate ephemeral key".
         *
         * In turn, Ephemeral Key must be conformed to the interface
         * "compute shared key".
         */
        set encryptionKey(encryptionKey) {
            Module._vscf_ecies_release_encryption_key(this.ctxPtr)
            Module._vscf_ecies_use_encryption_key(this.ctxPtr, encryptionKey.ctxPtr)
        }

        /**
         * Set private key that used for data decryption.
         *
         * Private Key must be conformed to the interface "compute shared key".
         */
        set decryptionKey(decryptionKey) {
            Module._vscf_ecies_release_decryption_key(this.ctxPtr)
            Module._vscf_ecies_use_decryption_key(this.ctxPtr, decryptionKey.ctxPtr)
        }

        /**
         * Set private key that used for data decryption.
         *
         * Ephemeral Key must be conformed to the interface "compute shared key".
         */
        set ephemeralKey(ephemeralKey) {
            Module._vscf_ecies_release_ephemeral_key(this.ctxPtr)
            Module._vscf_ecies_use_ephemeral_key(this.ctxPtr, ephemeralKey.ctxPtr)
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
                const proxyResult = Module._vscf_ecies_encrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
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
            proxyResult = Module._vscf_ecies_encrypted_len(this.ctxPtr, dataLen);
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
                const proxyResult = Module._vscf_ecies_decrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
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
            proxyResult = Module._vscf_ecies_decrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            const proxyResult = Module._vscf_ecies_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }
    }

    return Ecies;
};

module.exports = initEcies;
