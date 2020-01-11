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

const initUokmsServer = (Module, modules) => {
    /**
     * Class implements UOKMS for server-side.
     */
    class UokmsServer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'UokmsServer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_uokms_server_new();
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
            return new UokmsServer(Module._vsce_uokms_server_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new UokmsServer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_uokms_server_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_uokms_server_release_random(this.ctxPtr)
            Module._vsce_uokms_server_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_uokms_server_release_operation_random(this.ctxPtr)
            Module._vsce_uokms_server_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        /**
         * Setups dependencies with default values.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vsce_uokms_server_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        /**
         * Generates new NIST P-256 server key pair for some client
         */
        generateServerKeyPair() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const serverPrivateKeyCapacity = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const serverPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(serverPrivateKeyCapacity);

            const serverPublicKeyCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const serverPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(serverPublicKeyCapacity);

            try {
                const proxyResult = Module._vsce_uokms_server_generate_server_key_pair(this.ctxPtr, serverPrivateKeyCtxPtr, serverPublicKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const serverPrivateKeyPtr = Module._vsc_buffer_bytes(serverPrivateKeyCtxPtr);
                const serverPrivateKeyPtrLen = Module._vsc_buffer_len(serverPrivateKeyCtxPtr);
                const serverPrivateKey = Module.HEAPU8.slice(serverPrivateKeyPtr, serverPrivateKeyPtr + serverPrivateKeyPtrLen);

                const serverPublicKeyPtr = Module._vsc_buffer_bytes(serverPublicKeyCtxPtr);
                const serverPublicKeyPtrLen = Module._vsc_buffer_len(serverPublicKeyCtxPtr);
                const serverPublicKey = Module.HEAPU8.slice(serverPublicKeyPtr, serverPublicKeyPtr + serverPublicKeyPtrLen);
                return { serverPrivateKey, serverPublicKey };
            } finally {
                Module._vsc_buffer_delete(serverPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(serverPublicKeyCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit DecryptResponse
         */
        decryptResponseLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vsce_uokms_server_decrypt_response_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Processed client's decrypt request
         */
        processDecryptRequest(serverPrivateKey, decryptRequest) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('serverPrivateKey', serverPrivateKey);
            precondition.ensureByteArray('decryptRequest', decryptRequest);

            //  Copy bytes from JS memory to the WASM memory.
            const serverPrivateKeySize = serverPrivateKey.length * serverPrivateKey.BYTES_PER_ELEMENT;
            const serverPrivateKeyPtr = Module._malloc(serverPrivateKeySize);
            Module.HEAP8.set(serverPrivateKey, serverPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPrivateKeyCtxPtr = Module._malloc(serverPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPrivateKeyCtxPtr, serverPrivateKeyPtr, serverPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const decryptRequestSize = decryptRequest.length * decryptRequest.BYTES_PER_ELEMENT;
            const decryptRequestPtr = Module._malloc(decryptRequestSize);
            Module.HEAP8.set(decryptRequest, decryptRequestPtr);

            //  Create C structure vsc_data_t.
            const decryptRequestCtxSize = Module._vsc_data_ctx_size();
            const decryptRequestCtxPtr = Module._malloc(decryptRequestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(decryptRequestCtxPtr, decryptRequestPtr, decryptRequestSize);

            const decryptResponseCapacity = this.decryptResponseLen();
            const decryptResponseCtxPtr = Module._vsc_buffer_new_with_capacity(decryptResponseCapacity);

            try {
                const proxyResult = Module._vsce_uokms_server_process_decrypt_request(this.ctxPtr, serverPrivateKeyCtxPtr, decryptRequestCtxPtr, decryptResponseCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const decryptResponsePtr = Module._vsc_buffer_bytes(decryptResponseCtxPtr);
                const decryptResponsePtrLen = Module._vsc_buffer_len(decryptResponseCtxPtr);
                const decryptResponse = Module.HEAPU8.slice(decryptResponsePtr, decryptResponsePtr + decryptResponsePtrLen);
                return decryptResponse;
            } finally {
                Module._free(serverPrivateKeyPtr);
                Module._free(serverPrivateKeyCtxPtr);
                Module._free(decryptRequestPtr);
                Module._free(decryptRequestCtxPtr);
                Module._vsc_buffer_delete(decryptResponseCtxPtr);
            }
        }

        /**
         * Updates server's private and public keys and issues an update token for use on client's side
         */
        rotateKeys(serverPrivateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('serverPrivateKey', serverPrivateKey);

            //  Copy bytes from JS memory to the WASM memory.
            const serverPrivateKeySize = serverPrivateKey.length * serverPrivateKey.BYTES_PER_ELEMENT;
            const serverPrivateKeyPtr = Module._malloc(serverPrivateKeySize);
            Module.HEAP8.set(serverPrivateKey, serverPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPrivateKeyCtxPtr = Module._malloc(serverPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPrivateKeyCtxPtr, serverPrivateKeyPtr, serverPrivateKeySize);

            const newServerPrivateKeyCapacity = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const newServerPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPrivateKeyCapacity);

            const newServerPublicKeyCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const newServerPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPublicKeyCapacity);

            const updateTokenCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const updateTokenCtxPtr = Module._vsc_buffer_new_with_capacity(updateTokenCapacity);

            try {
                const proxyResult = Module._vsce_uokms_server_rotate_keys(this.ctxPtr, serverPrivateKeyCtxPtr, newServerPrivateKeyCtxPtr, newServerPublicKeyCtxPtr, updateTokenCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const newServerPrivateKeyPtr = Module._vsc_buffer_bytes(newServerPrivateKeyCtxPtr);
                const newServerPrivateKeyPtrLen = Module._vsc_buffer_len(newServerPrivateKeyCtxPtr);
                const newServerPrivateKey = Module.HEAPU8.slice(newServerPrivateKeyPtr, newServerPrivateKeyPtr + newServerPrivateKeyPtrLen);

                const newServerPublicKeyPtr = Module._vsc_buffer_bytes(newServerPublicKeyCtxPtr);
                const newServerPublicKeyPtrLen = Module._vsc_buffer_len(newServerPublicKeyCtxPtr);
                const newServerPublicKey = Module.HEAPU8.slice(newServerPublicKeyPtr, newServerPublicKeyPtr + newServerPublicKeyPtrLen);

                const updateTokenPtr = Module._vsc_buffer_bytes(updateTokenCtxPtr);
                const updateTokenPtrLen = Module._vsc_buffer_len(updateTokenCtxPtr);
                const updateToken = Module.HEAPU8.slice(updateTokenPtr, updateTokenPtr + updateTokenPtrLen);
                return { newServerPrivateKey, newServerPublicKey, updateToken };
            } finally {
                Module._free(serverPrivateKeyPtr);
                Module._free(serverPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(newServerPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(newServerPublicKeyCtxPtr);
                Module._vsc_buffer_delete(updateTokenCtxPtr);
            }
        }
    }

    return UokmsServer;
};

module.exports = initUokmsServer;
