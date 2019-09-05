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

const initPheCipher = (Module, modules) => {
    /**
     * Class for encryption using PHE account key
     * This class is thread-safe.
     */
    class PheCipher {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PheCipher';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_phe_cipher_new();
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
            return new PheCipher(Module._vsce_phe_cipher_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PheCipher(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_phe_cipher_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for salt generation
         */
        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_phe_cipher_release_random(this.ctxPtr)
            Module._vsce_phe_cipher_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Setups dependencies with default values.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vsce_phe_cipher_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        /**
         * Returns buffer capacity needed to fit cipher text
         */
        encryptLen(plainTextLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('plainTextLen', plainTextLen);

            let proxyResult;
            proxyResult = Module._vsce_phe_cipher_encrypt_len(this.ctxPtr, plainTextLen);
            return proxyResult;
        }

        /**
         * Returns buffer capacity needed to fit plain text
         */
        decryptLen(cipherTextLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('cipherTextLen', cipherTextLen);

            let proxyResult;
            proxyResult = Module._vsce_phe_cipher_decrypt_len(this.ctxPtr, cipherTextLen);
            return proxyResult;
        }

        /**
         * Encrypts data using account key
         */
        encrypt(plainText, accountKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('plainText', plainText);
            precondition.ensureByteArray('accountKey', accountKey);

            //  Copy bytes from JS memory to the WASM memory.
            const plainTextSize = plainText.length * plainText.BYTES_PER_ELEMENT;
            const plainTextPtr = Module._malloc(plainTextSize);
            Module.HEAP8.set(plainText, plainTextPtr);

            //  Create C structure vsc_data_t.
            const plainTextCtxSize = Module._vsc_data_ctx_size();
            const plainTextCtxPtr = Module._malloc(plainTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plainTextCtxPtr, plainTextPtr, plainTextSize);

            //  Copy bytes from JS memory to the WASM memory.
            const accountKeySize = accountKey.length * accountKey.BYTES_PER_ELEMENT;
            const accountKeyPtr = Module._malloc(accountKeySize);
            Module.HEAP8.set(accountKey, accountKeyPtr);

            //  Create C structure vsc_data_t.
            const accountKeyCtxSize = Module._vsc_data_ctx_size();
            const accountKeyCtxPtr = Module._malloc(accountKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(accountKeyCtxPtr, accountKeyPtr, accountKeySize);

            const cipherTextCapacity = this.encryptLen(plainText.length);
            const cipherTextCtxPtr = Module._vsc_buffer_new_with_capacity(cipherTextCapacity);

            try {
                const proxyResult = Module._vsce_phe_cipher_encrypt(this.ctxPtr, plainTextCtxPtr, accountKeyCtxPtr, cipherTextCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const cipherTextPtr = Module._vsc_buffer_bytes(cipherTextCtxPtr);
                const cipherTextPtrLen = Module._vsc_buffer_len(cipherTextCtxPtr);
                const cipherText = Module.HEAPU8.slice(cipherTextPtr, cipherTextPtr + cipherTextPtrLen);
                return cipherText;
            } finally {
                Module._free(plainTextPtr);
                Module._free(plainTextCtxPtr);
                Module._free(accountKeyPtr);
                Module._free(accountKeyCtxPtr);
                Module._vsc_buffer_delete(cipherTextCtxPtr);
            }
        }

        /**
         * Decrypts data using account key
         */
        decrypt(cipherText, accountKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('cipherText', cipherText);
            precondition.ensureByteArray('accountKey', accountKey);

            //  Copy bytes from JS memory to the WASM memory.
            const cipherTextSize = cipherText.length * cipherText.BYTES_PER_ELEMENT;
            const cipherTextPtr = Module._malloc(cipherTextSize);
            Module.HEAP8.set(cipherText, cipherTextPtr);

            //  Create C structure vsc_data_t.
            const cipherTextCtxSize = Module._vsc_data_ctx_size();
            const cipherTextCtxPtr = Module._malloc(cipherTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(cipherTextCtxPtr, cipherTextPtr, cipherTextSize);

            //  Copy bytes from JS memory to the WASM memory.
            const accountKeySize = accountKey.length * accountKey.BYTES_PER_ELEMENT;
            const accountKeyPtr = Module._malloc(accountKeySize);
            Module.HEAP8.set(accountKey, accountKeyPtr);

            //  Create C structure vsc_data_t.
            const accountKeyCtxSize = Module._vsc_data_ctx_size();
            const accountKeyCtxPtr = Module._malloc(accountKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(accountKeyCtxPtr, accountKeyPtr, accountKeySize);

            const plainTextCapacity = this.decryptLen(cipherText.length);
            const plainTextCtxPtr = Module._vsc_buffer_new_with_capacity(plainTextCapacity);

            try {
                const proxyResult = Module._vsce_phe_cipher_decrypt(this.ctxPtr, cipherTextCtxPtr, accountKeyCtxPtr, plainTextCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const plainTextPtr = Module._vsc_buffer_bytes(plainTextCtxPtr);
                const plainTextPtrLen = Module._vsc_buffer_len(plainTextCtxPtr);
                const plainText = Module.HEAPU8.slice(plainTextPtr, plainTextPtr + plainTextPtrLen);
                return plainText;
            } finally {
                Module._free(cipherTextPtr);
                Module._free(cipherTextCtxPtr);
                Module._free(accountKeyPtr);
                Module._free(accountKeyCtxPtr);
                Module._vsc_buffer_delete(plainTextCtxPtr);
            }
        }

        /**
         * Encrypts data (and authenticates additional data) using account key
         */
        authEncrypt(plainText, additionalData, accountKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('plainText', plainText);
            precondition.ensureByteArray('additionalData', additionalData);
            precondition.ensureByteArray('accountKey', accountKey);

            //  Copy bytes from JS memory to the WASM memory.
            const plainTextSize = plainText.length * plainText.BYTES_PER_ELEMENT;
            const plainTextPtr = Module._malloc(plainTextSize);
            Module.HEAP8.set(plainText, plainTextPtr);

            //  Create C structure vsc_data_t.
            const plainTextCtxSize = Module._vsc_data_ctx_size();
            const plainTextCtxPtr = Module._malloc(plainTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plainTextCtxPtr, plainTextPtr, plainTextSize);

            //  Copy bytes from JS memory to the WASM memory.
            const additionalDataSize = additionalData.length * additionalData.BYTES_PER_ELEMENT;
            const additionalDataPtr = Module._malloc(additionalDataSize);
            Module.HEAP8.set(additionalData, additionalDataPtr);

            //  Create C structure vsc_data_t.
            const additionalDataCtxSize = Module._vsc_data_ctx_size();
            const additionalDataCtxPtr = Module._malloc(additionalDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(additionalDataCtxPtr, additionalDataPtr, additionalDataSize);

            //  Copy bytes from JS memory to the WASM memory.
            const accountKeySize = accountKey.length * accountKey.BYTES_PER_ELEMENT;
            const accountKeyPtr = Module._malloc(accountKeySize);
            Module.HEAP8.set(accountKey, accountKeyPtr);

            //  Create C structure vsc_data_t.
            const accountKeyCtxSize = Module._vsc_data_ctx_size();
            const accountKeyCtxPtr = Module._malloc(accountKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(accountKeyCtxPtr, accountKeyPtr, accountKeySize);

            const cipherTextCapacity = this.encryptLen(plainText.length);
            const cipherTextCtxPtr = Module._vsc_buffer_new_with_capacity(cipherTextCapacity);

            try {
                const proxyResult = Module._vsce_phe_cipher_auth_encrypt(this.ctxPtr, plainTextCtxPtr, additionalDataCtxPtr, accountKeyCtxPtr, cipherTextCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const cipherTextPtr = Module._vsc_buffer_bytes(cipherTextCtxPtr);
                const cipherTextPtrLen = Module._vsc_buffer_len(cipherTextCtxPtr);
                const cipherText = Module.HEAPU8.slice(cipherTextPtr, cipherTextPtr + cipherTextPtrLen);
                return cipherText;
            } finally {
                Module._free(plainTextPtr);
                Module._free(plainTextCtxPtr);
                Module._free(additionalDataPtr);
                Module._free(additionalDataCtxPtr);
                Module._free(accountKeyPtr);
                Module._free(accountKeyCtxPtr);
                Module._vsc_buffer_delete(cipherTextCtxPtr);
            }
        }

        /**
         * Decrypts data (and verifies additional data) using account key
         */
        authDecrypt(cipherText, additionalData, accountKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('cipherText', cipherText);
            precondition.ensureByteArray('additionalData', additionalData);
            precondition.ensureByteArray('accountKey', accountKey);

            //  Copy bytes from JS memory to the WASM memory.
            const cipherTextSize = cipherText.length * cipherText.BYTES_PER_ELEMENT;
            const cipherTextPtr = Module._malloc(cipherTextSize);
            Module.HEAP8.set(cipherText, cipherTextPtr);

            //  Create C structure vsc_data_t.
            const cipherTextCtxSize = Module._vsc_data_ctx_size();
            const cipherTextCtxPtr = Module._malloc(cipherTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(cipherTextCtxPtr, cipherTextPtr, cipherTextSize);

            //  Copy bytes from JS memory to the WASM memory.
            const additionalDataSize = additionalData.length * additionalData.BYTES_PER_ELEMENT;
            const additionalDataPtr = Module._malloc(additionalDataSize);
            Module.HEAP8.set(additionalData, additionalDataPtr);

            //  Create C structure vsc_data_t.
            const additionalDataCtxSize = Module._vsc_data_ctx_size();
            const additionalDataCtxPtr = Module._malloc(additionalDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(additionalDataCtxPtr, additionalDataPtr, additionalDataSize);

            //  Copy bytes from JS memory to the WASM memory.
            const accountKeySize = accountKey.length * accountKey.BYTES_PER_ELEMENT;
            const accountKeyPtr = Module._malloc(accountKeySize);
            Module.HEAP8.set(accountKey, accountKeyPtr);

            //  Create C structure vsc_data_t.
            const accountKeyCtxSize = Module._vsc_data_ctx_size();
            const accountKeyCtxPtr = Module._malloc(accountKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(accountKeyCtxPtr, accountKeyPtr, accountKeySize);

            const plainTextCapacity = this.decryptLen(cipherText.length);
            const plainTextCtxPtr = Module._vsc_buffer_new_with_capacity(plainTextCapacity);

            try {
                const proxyResult = Module._vsce_phe_cipher_auth_decrypt(this.ctxPtr, cipherTextCtxPtr, additionalDataCtxPtr, accountKeyCtxPtr, plainTextCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const plainTextPtr = Module._vsc_buffer_bytes(plainTextCtxPtr);
                const plainTextPtrLen = Module._vsc_buffer_len(plainTextCtxPtr);
                const plainText = Module.HEAPU8.slice(plainTextPtr, plainTextPtr + plainTextPtrLen);
                return plainText;
            } finally {
                Module._free(cipherTextPtr);
                Module._free(cipherTextCtxPtr);
                Module._free(additionalDataPtr);
                Module._free(additionalDataCtxPtr);
                Module._free(accountKeyPtr);
                Module._free(accountKeyCtxPtr);
                Module._vsc_buffer_delete(plainTextCtxPtr);
            }
        }
    }

    return PheCipher;
};

module.exports = initPheCipher;
