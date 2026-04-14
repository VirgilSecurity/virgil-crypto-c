/**
 * Copyright (C) 2015-2022 Virgil Security, Inc.
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

const initAes256Gcm = (Module, modules) => {
    class Aes256Gcm {

        constructor(ctxPtr) {
            this.name = 'Aes256Gcm';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_aes256_gcm_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Aes256Gcm(Module._vscf_aes256_gcm_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Aes256Gcm(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_aes256_gcm_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_alg_id(this.ctxPtr);
            return proxyResult;
        }

        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_aes256_gcm_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        encrypt(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.encryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_encrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
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

        encryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_encrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        preciseEncryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_precise_encrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        decrypt(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.decryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_decrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
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

        decryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_decrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        static get NONCE_LEN() {
            return 12;
        }

        get NONCE_LEN() {
            return 12;
        }

        static get KEY_LEN() {
            return 32;
        }

        get KEY_LEN() {
            return 32;
        }

        static get KEY_BITLEN() {
            return 256;
        }

        get KEY_BITLEN() {
            return 256;
        }

        static get BLOCK_LEN() {
            return 16;
        }

        get BLOCK_LEN() {
            return 16;
        }

        setNonce(nonce) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('nonce', nonce);

            // Copy bytes from JS memory to the WASM memory.
            const nonceSize = nonce.length * nonce.BYTES_PER_ELEMENT;
            const noncePtr = Module._malloc(nonceSize);
            Module.HEAP8.set(nonce, noncePtr);

            // Create C structure vsc_data_t.
            const nonceCtxSize = Module._vsc_data_ctx_size();
            const nonceCtxPtr = Module._malloc(nonceCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(nonceCtxPtr, noncePtr, nonceSize);

            try {
                Module._vscf_aes256_gcm_set_nonce(this.ctxPtr, nonceCtxPtr);
            } finally {
                Module._free(noncePtr);
                Module._free(nonceCtxPtr);
            }
        }

        setKey(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            try {
                Module._vscf_aes256_gcm_set_key(this.ctxPtr, keyCtxPtr);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
            }
        }

        state() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_state(this.ctxPtr);
            return proxyResult;
        }

        startEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_aes256_gcm_start_encryption(this.ctxPtr);
        }

        startDecryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_aes256_gcm_start_decryption(this.ctxPtr);
        }

        update(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.outLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                Module._vscf_aes256_gcm_update(this.ctxPtr, dataCtxPtr, outCtxPtr);

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

        outLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        encryptedOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_encrypted_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        decryptedOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_decrypted_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        finish() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const outCapacity = this.outLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_finish(this.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        static get AUTH_TAG_LEN() {
            return 16;
        }

        get AUTH_TAG_LEN() {
            return 16;
        }

        authEncrypt(data, authData) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            precondition.ensureByteArray('authData', authData);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            // Copy bytes from JS memory to the WASM memory.
            const authDataSize = authData.length * authData.BYTES_PER_ELEMENT;
            const authDataPtr = Module._malloc(authDataSize);
            Module.HEAP8.set(authData, authDataPtr);

            // Create C structure vsc_data_t.
            const authDataCtxSize = Module._vsc_data_ctx_size();
            const authDataCtxPtr = Module._malloc(authDataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(authDataCtxPtr, authDataPtr, authDataSize);

            const outCapacity = this.authEncryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            const tagCapacity = this.AUTH_TAG_LEN;
            const tagCtxPtr = Module._vsc_buffer_new_with_capacity(tagCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_auth_encrypt(this.ctxPtr, dataCtxPtr, authDataCtxPtr, outCtxPtr, tagCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);

                const tagPtr = Module._vsc_buffer_bytes(tagCtxPtr);
                const tagPtrLen = Module._vsc_buffer_len(tagCtxPtr);
                const tag = Module.HEAPU8.slice(tagPtr, tagPtr + tagPtrLen);
                return { out, tag };
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(authDataPtr);
                Module._free(authDataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
                Module._vsc_buffer_delete(tagCtxPtr);
            }
        }

        authEncryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_auth_encrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        authDecrypt(data, authData, tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            precondition.ensureByteArray('authData', authData);
            precondition.ensureByteArray('tag', tag);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            // Copy bytes from JS memory to the WASM memory.
            const authDataSize = authData.length * authData.BYTES_PER_ELEMENT;
            const authDataPtr = Module._malloc(authDataSize);
            Module.HEAP8.set(authData, authDataPtr);

            // Create C structure vsc_data_t.
            const authDataCtxSize = Module._vsc_data_ctx_size();
            const authDataCtxPtr = Module._malloc(authDataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(authDataCtxPtr, authDataPtr, authDataSize);

            // Copy bytes from JS memory to the WASM memory.
            const tagSize = tag.length * tag.BYTES_PER_ELEMENT;
            const tagPtr = Module._malloc(tagSize);
            Module.HEAP8.set(tag, tagPtr);

            // Create C structure vsc_data_t.
            const tagCtxSize = Module._vsc_data_ctx_size();
            const tagCtxPtr = Module._malloc(tagCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(tagCtxPtr, tagPtr, tagSize);

            const outCapacity = this.authDecryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_auth_decrypt(this.ctxPtr, dataCtxPtr, authDataCtxPtr, tagCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(authDataPtr);
                Module._free(authDataCtxPtr);
                Module._free(tagPtr);
                Module._free(tagCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        authDecryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_aes256_gcm_auth_decrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        setAuthData(authData) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('authData', authData);

            // Copy bytes from JS memory to the WASM memory.
            const authDataSize = authData.length * authData.BYTES_PER_ELEMENT;
            const authDataPtr = Module._malloc(authDataSize);
            Module.HEAP8.set(authData, authDataPtr);

            // Create C structure vsc_data_t.
            const authDataCtxSize = Module._vsc_data_ctx_size();
            const authDataCtxPtr = Module._malloc(authDataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(authDataCtxPtr, authDataPtr, authDataSize);

            try {
                Module._vscf_aes256_gcm_set_auth_data(this.ctxPtr, authDataCtxPtr);
            } finally {
                Module._free(authDataPtr);
                Module._free(authDataCtxPtr);
            }
        }

        finishAuthEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const outCapacity = this.outLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            const tagCapacity = this.AUTH_TAG_LEN;
            const tagCtxPtr = Module._vsc_buffer_new_with_capacity(tagCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_finish_auth_encryption(this.ctxPtr, outCtxPtr, tagCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);

                const tagPtr = Module._vsc_buffer_bytes(tagCtxPtr);
                const tagPtrLen = Module._vsc_buffer_len(tagCtxPtr);
                const tag = Module.HEAPU8.slice(tagPtr, tagPtr + tagPtrLen);
                return { out, tag };
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
                Module._vsc_buffer_delete(tagCtxPtr);
            }
        }

        finishAuthDecryption(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('tag', tag);

            // Copy bytes from JS memory to the WASM memory.
            const tagSize = tag.length * tag.BYTES_PER_ELEMENT;
            const tagPtr = Module._malloc(tagSize);
            Module.HEAP8.set(tag, tagPtr);

            // Create C structure vsc_data_t.
            const tagCtxSize = Module._vsc_data_ctx_size();
            const tagCtxPtr = Module._malloc(tagCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(tagCtxPtr, tagPtr, tagSize);

            const outCapacity = this.outLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_aes256_gcm_finish_auth_decryption(this.ctxPtr, tagCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(tagPtr);
                Module._free(tagCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

    }

    return Aes256Gcm;
};

module.exports = initAes256Gcm;
