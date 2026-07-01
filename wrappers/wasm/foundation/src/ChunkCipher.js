/**
 * Copyright (C) 2015-2026 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

const initChunkCipher = (Module, modules) => {
    class ChunkCipher {

        constructor(ctxPtr) {
            this.name = 'ChunkCipher';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_chunk_cipher_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new ChunkCipher(Module._vscf_chunk_cipher_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new ChunkCipher(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_chunk_cipher_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_chunk_cipher_release_random(this.ctxPtr)
            Module._vscf_chunk_cipher_use_random(this.ctxPtr, random.ctxPtr)
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
                Module._vscf_chunk_cipher_set_key(this.ctxPtr, keyCtxPtr);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
            }
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
                Module._vscf_chunk_cipher_set_nonce(this.ctxPtr, nonceCtxPtr);
            } finally {
                Module._free(noncePtr);
                Module._free(nonceCtxPtr);
            }
        }

        setChunkSize(chunkSize) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('chunkSize', chunkSize);
            Module._vscf_chunk_cipher_set_chunk_size(this.ctxPtr, chunkSize);
        }

        nonce() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_chunk_cipher_nonce(this.ctxPtr);
        }

        nonceLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_chunk_cipher_nonce_len(this.ctxPtr);
            return proxyResult;
        }

        encryptionOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_chunk_cipher_encryption_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        startEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_chunk_cipher_start_encryption(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        processEncryption(data) {
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
            
            const outCapacity = this.encryptionOutLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_process_encryption(this.ctxPtr, dataCtxPtr, outCtxPtr);
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

        finishEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const outCapacity = this.encryptionOutLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_finish_encryption(this.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        decryptionOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_chunk_cipher_decryption_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        startDecryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_chunk_cipher_start_decryption(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        processDecryption(data) {
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
            
            const outCapacity = this.decryptionOutLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_process_decryption(this.ctxPtr, dataCtxPtr, outCtxPtr);
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

        finishDecryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const outCapacity = this.decryptionOutLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_finish_decryption(this.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        chunkCount(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_chunk_cipher_chunk_count(this.ctxPtr, dataLen);
            return proxyResult;
        }

        encryptAt(chunkIndex, isLast, plaintext) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('chunkIndex', chunkIndex);
            precondition.ensureBoolean('isLast', isLast);
            precondition.ensureByteArray('plaintext', plaintext);
            
            // Copy bytes from JS memory to the WASM memory.
            const plaintextSize = plaintext.length * plaintext.BYTES_PER_ELEMENT;
            const plaintextPtr = Module._malloc(plaintextSize);
            Module.HEAP8.set(plaintext, plaintextPtr);
            
            // Create C structure vsc_data_t.
            const plaintextCtxSize = Module._vsc_data_ctx_size();
            const plaintextCtxPtr = Module._malloc(plaintextCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plaintextCtxPtr, plaintextPtr, plaintextSize);
            
            const outCapacity = this.encryptionOutLen(plaintext.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_encrypt_at(this.ctxPtr, chunkIndex, isLast, plaintextCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(plaintextPtr);
                Module._free(plaintextCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        decryptAt(chunkIndex, isLast, frame) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('chunkIndex', chunkIndex);
            precondition.ensureBoolean('isLast', isLast);
            precondition.ensureByteArray('frame', frame);
            
            // Copy bytes from JS memory to the WASM memory.
            const frameSize = frame.length * frame.BYTES_PER_ELEMENT;
            const framePtr = Module._malloc(frameSize);
            Module.HEAP8.set(frame, framePtr);
            
            // Create C structure vsc_data_t.
            const frameCtxSize = Module._vsc_data_ctx_size();
            const frameCtxPtr = Module._malloc(frameCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(frameCtxPtr, framePtr, frameSize);
            
            const outCapacity = this.decryptionOutLen(frame.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_chunk_cipher_decrypt_at(this.ctxPtr, chunkIndex, isLast, frameCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(framePtr);
                Module._free(frameCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

    }

    return ChunkCipher;
};

module.exports = initChunkCipher;
