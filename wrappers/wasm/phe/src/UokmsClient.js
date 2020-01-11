/**
 * Copyright (C) 2015-2020 Virgil Security, Inc.
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

const initUokmsClient = (Module, modules) => {
    /**
     * Class implements UOKMS for client-side.
     */
    class UokmsClient {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'UokmsClient';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_uokms_client_new();
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
            return new UokmsClient(Module._vsce_uokms_client_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new UokmsClient(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_uokms_client_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_uokms_client_release_random(this.ctxPtr)
            Module._vsce_uokms_client_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_uokms_client_release_operation_random(this.ctxPtr)
            Module._vsce_uokms_client_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        /**
         * Setups dependencies with default values.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vsce_uokms_client_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        /**
         * Sets client private and server public key
         * Call this method before any other methods
         * This function should be called only once
         */
        setKeys(clientPrivateKey, serverPublicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('clientPrivateKey', clientPrivateKey);
            precondition.ensureByteArray('serverPublicKey', serverPublicKey);

            //  Copy bytes from JS memory to the WASM memory.
            const clientPrivateKeySize = clientPrivateKey.length * clientPrivateKey.BYTES_PER_ELEMENT;
            const clientPrivateKeyPtr = Module._malloc(clientPrivateKeySize);
            Module.HEAP8.set(clientPrivateKey, clientPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const clientPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const clientPrivateKeyCtxPtr = Module._malloc(clientPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(clientPrivateKeyCtxPtr, clientPrivateKeyPtr, clientPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const serverPublicKeySize = serverPublicKey.length * serverPublicKey.BYTES_PER_ELEMENT;
            const serverPublicKeyPtr = Module._malloc(serverPublicKeySize);
            Module.HEAP8.set(serverPublicKey, serverPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPublicKeyCtxPtr = Module._malloc(serverPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPublicKeyCtxPtr, serverPublicKeyPtr, serverPublicKeySize);

            try {
                const proxyResult = Module._vsce_uokms_client_set_keys(this.ctxPtr, clientPrivateKeyCtxPtr, serverPublicKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);
            } finally {
                Module._free(clientPrivateKeyPtr);
                Module._free(clientPrivateKeyCtxPtr);
                Module._free(serverPublicKeyPtr);
                Module._free(serverPublicKeyCtxPtr);
            }
        }

        /**
         * Generates client private key
         */
        generateClientPrivateKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const clientPrivateKeyCapacity = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const clientPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(clientPrivateKeyCapacity);

            try {
                const proxyResult = Module._vsce_uokms_client_generate_client_private_key(this.ctxPtr, clientPrivateKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const clientPrivateKeyPtr = Module._vsc_buffer_bytes(clientPrivateKeyCtxPtr);
                const clientPrivateKeyPtrLen = Module._vsc_buffer_len(clientPrivateKeyCtxPtr);
                const clientPrivateKey = Module.HEAPU8.slice(clientPrivateKeyPtr, clientPrivateKeyPtr + clientPrivateKeyPtrLen);
                return clientPrivateKey;
            } finally {
                Module._vsc_buffer_delete(clientPrivateKeyCtxPtr);
            }
        }

        /**
         * Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
         * of "encryption key len" that can be used for symmetric encryption
         */
        generateEncryptWrap(encryptionKeyLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('encryptionKeyLen', encryptionKeyLen);

            const wrapCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const wrapCtxPtr = Module._vsc_buffer_new_with_capacity(wrapCapacity);

            const encryptionKeyCapacity = encryptionKeyLen;
            const encryptionKeyCtxPtr = Module._vsc_buffer_new_with_capacity(encryptionKeyCapacity);

            try {
                const proxyResult = Module._vsce_uokms_client_generate_encrypt_wrap(this.ctxPtr, wrapCtxPtr, encryptionKeyLen, encryptionKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const wrapPtr = Module._vsc_buffer_bytes(wrapCtxPtr);
                const wrapPtrLen = Module._vsc_buffer_len(wrapCtxPtr);
                const wrap = Module.HEAPU8.slice(wrapPtr, wrapPtr + wrapPtrLen);

                const encryptionKeyPtr = Module._vsc_buffer_bytes(encryptionKeyCtxPtr);
                const encryptionKeyPtrLen = Module._vsc_buffer_len(encryptionKeyCtxPtr);
                const encryptionKey = Module.HEAPU8.slice(encryptionKeyPtr, encryptionKeyPtr + encryptionKeyPtrLen);
                return { wrap, encryptionKey };
            } finally {
                Module._vsc_buffer_delete(wrapCtxPtr);
                Module._vsc_buffer_delete(encryptionKeyCtxPtr);
            }
        }

        /**
         * Generates request to decrypt data, this request should be sent to the server.
         * Server response is then passed to "process decrypt response" where encryption key can be decapsulated
         */
        generateDecryptRequest(wrap) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('wrap', wrap);

            //  Copy bytes from JS memory to the WASM memory.
            const wrapSize = wrap.length * wrap.BYTES_PER_ELEMENT;
            const wrapPtr = Module._malloc(wrapSize);
            Module.HEAP8.set(wrap, wrapPtr);

            //  Create C structure vsc_data_t.
            const wrapCtxSize = Module._vsc_data_ctx_size();
            const wrapCtxPtr = Module._malloc(wrapCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(wrapCtxPtr, wrapPtr, wrapSize);

            const deblindFactorCapacity = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const deblindFactorCtxPtr = Module._vsc_buffer_new_with_capacity(deblindFactorCapacity);

            const decryptRequestCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const decryptRequestCtxPtr = Module._vsc_buffer_new_with_capacity(decryptRequestCapacity);

            try {
                const proxyResult = Module._vsce_uokms_client_generate_decrypt_request(this.ctxPtr, wrapCtxPtr, deblindFactorCtxPtr, decryptRequestCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const deblindFactorPtr = Module._vsc_buffer_bytes(deblindFactorCtxPtr);
                const deblindFactorPtrLen = Module._vsc_buffer_len(deblindFactorCtxPtr);
                const deblindFactor = Module.HEAPU8.slice(deblindFactorPtr, deblindFactorPtr + deblindFactorPtrLen);

                const decryptRequestPtr = Module._vsc_buffer_bytes(decryptRequestCtxPtr);
                const decryptRequestPtrLen = Module._vsc_buffer_len(decryptRequestCtxPtr);
                const decryptRequest = Module.HEAPU8.slice(decryptRequestPtr, decryptRequestPtr + decryptRequestPtrLen);
                return { deblindFactor, decryptRequest };
            } finally {
                Module._free(wrapPtr);
                Module._free(wrapCtxPtr);
                Module._vsc_buffer_delete(deblindFactorCtxPtr);
                Module._vsc_buffer_delete(decryptRequestCtxPtr);
            }
        }

        /**
         * Processed server response, checks server proof and decapsulates encryption key
         */
        processDecryptResponse(wrap, decryptRequest, decryptResponse, deblindFactor, encryptionKeyLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('wrap', wrap);
            precondition.ensureByteArray('decryptRequest', decryptRequest);
            precondition.ensureByteArray('decryptResponse', decryptResponse);
            precondition.ensureByteArray('deblindFactor', deblindFactor);
            precondition.ensureNumber('encryptionKeyLen', encryptionKeyLen);

            //  Copy bytes from JS memory to the WASM memory.
            const wrapSize = wrap.length * wrap.BYTES_PER_ELEMENT;
            const wrapPtr = Module._malloc(wrapSize);
            Module.HEAP8.set(wrap, wrapPtr);

            //  Create C structure vsc_data_t.
            const wrapCtxSize = Module._vsc_data_ctx_size();
            const wrapCtxPtr = Module._malloc(wrapCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(wrapCtxPtr, wrapPtr, wrapSize);

            //  Copy bytes from JS memory to the WASM memory.
            const decryptRequestSize = decryptRequest.length * decryptRequest.BYTES_PER_ELEMENT;
            const decryptRequestPtr = Module._malloc(decryptRequestSize);
            Module.HEAP8.set(decryptRequest, decryptRequestPtr);

            //  Create C structure vsc_data_t.
            const decryptRequestCtxSize = Module._vsc_data_ctx_size();
            const decryptRequestCtxPtr = Module._malloc(decryptRequestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(decryptRequestCtxPtr, decryptRequestPtr, decryptRequestSize);

            //  Copy bytes from JS memory to the WASM memory.
            const decryptResponseSize = decryptResponse.length * decryptResponse.BYTES_PER_ELEMENT;
            const decryptResponsePtr = Module._malloc(decryptResponseSize);
            Module.HEAP8.set(decryptResponse, decryptResponsePtr);

            //  Create C structure vsc_data_t.
            const decryptResponseCtxSize = Module._vsc_data_ctx_size();
            const decryptResponseCtxPtr = Module._malloc(decryptResponseCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(decryptResponseCtxPtr, decryptResponsePtr, decryptResponseSize);

            //  Copy bytes from JS memory to the WASM memory.
            const deblindFactorSize = deblindFactor.length * deblindFactor.BYTES_PER_ELEMENT;
            const deblindFactorPtr = Module._malloc(deblindFactorSize);
            Module.HEAP8.set(deblindFactor, deblindFactorPtr);

            //  Create C structure vsc_data_t.
            const deblindFactorCtxSize = Module._vsc_data_ctx_size();
            const deblindFactorCtxPtr = Module._malloc(deblindFactorCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(deblindFactorCtxPtr, deblindFactorPtr, deblindFactorSize);

            const encryptionKeyCapacity = encryptionKeyLen;
            const encryptionKeyCtxPtr = Module._vsc_buffer_new_with_capacity(encryptionKeyCapacity);

            try {
                const proxyResult = Module._vsce_uokms_client_process_decrypt_response(this.ctxPtr, wrapCtxPtr, decryptRequestCtxPtr, decryptResponseCtxPtr, deblindFactorCtxPtr, encryptionKeyLen, encryptionKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const encryptionKeyPtr = Module._vsc_buffer_bytes(encryptionKeyCtxPtr);
                const encryptionKeyPtrLen = Module._vsc_buffer_len(encryptionKeyCtxPtr);
                const encryptionKey = Module.HEAPU8.slice(encryptionKeyPtr, encryptionKeyPtr + encryptionKeyPtrLen);
                return encryptionKey;
            } finally {
                Module._free(wrapPtr);
                Module._free(wrapCtxPtr);
                Module._free(decryptRequestPtr);
                Module._free(decryptRequestCtxPtr);
                Module._free(decryptResponsePtr);
                Module._free(decryptResponseCtxPtr);
                Module._free(deblindFactorPtr);
                Module._free(deblindFactorCtxPtr);
                Module._vsc_buffer_delete(encryptionKeyCtxPtr);
            }
        }

        /**
         * Rotates client and server keys using given update token obtained from server
         */
        rotateKeys(updateToken) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('updateToken', updateToken);

            //  Copy bytes from JS memory to the WASM memory.
            const updateTokenSize = updateToken.length * updateToken.BYTES_PER_ELEMENT;
            const updateTokenPtr = Module._malloc(updateTokenSize);
            Module.HEAP8.set(updateToken, updateTokenPtr);

            //  Create C structure vsc_data_t.
            const updateTokenCtxSize = Module._vsc_data_ctx_size();
            const updateTokenCtxPtr = Module._malloc(updateTokenCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(updateTokenCtxPtr, updateTokenPtr, updateTokenSize);

            const newClientPrivateKeyCapacity = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const newClientPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newClientPrivateKeyCapacity);

            const newServerPublicKeyCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const newServerPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPublicKeyCapacity);

            try {
                const proxyResult = Module._vsce_uokms_client_rotate_keys(this.ctxPtr, updateTokenCtxPtr, newClientPrivateKeyCtxPtr, newServerPublicKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const newClientPrivateKeyPtr = Module._vsc_buffer_bytes(newClientPrivateKeyCtxPtr);
                const newClientPrivateKeyPtrLen = Module._vsc_buffer_len(newClientPrivateKeyCtxPtr);
                const newClientPrivateKey = Module.HEAPU8.slice(newClientPrivateKeyPtr, newClientPrivateKeyPtr + newClientPrivateKeyPtrLen);

                const newServerPublicKeyPtr = Module._vsc_buffer_bytes(newServerPublicKeyCtxPtr);
                const newServerPublicKeyPtrLen = Module._vsc_buffer_len(newServerPublicKeyCtxPtr);
                const newServerPublicKey = Module.HEAPU8.slice(newServerPublicKeyPtr, newServerPublicKeyPtr + newServerPublicKeyPtrLen);
                return { newClientPrivateKey, newServerPublicKey };
            } finally {
                Module._free(updateTokenPtr);
                Module._free(updateTokenCtxPtr);
                Module._vsc_buffer_delete(newClientPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(newServerPublicKeyCtxPtr);
            }
        }
    }

    return UokmsClient;
};

module.exports = initUokmsClient;
