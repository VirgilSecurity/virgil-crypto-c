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


const initPheServer = (Module, modules) => {
    /**
     * Class for server-side PHE crypto operations.
     * This class is thread-safe in case if VSCE_MULTI_THREAD defined
     */
    class PheServer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PheServer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_phe_server_new();
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
            return new PheServer(Module._vsce_phe_server_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PheServer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_phe_server_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            Module._vsce_phe_server_release_random(this.ctxPtr)
            Module._vsce_phe_server_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            Module._vsce_phe_server_release_operation_random(this.ctxPtr)
            Module._vsce_phe_server_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        setupDefaults() {
            const proxyResult = Module._vsce_phe_server_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        /**
         * Generates new NIST P-256 server key pair for some client
         */
        generateServerKeyPair() {
            const serverPrivateKeySize = PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const serverPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(serverPrivateKeySize);

            const serverPublicKeySize = PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const serverPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(serverPublicKeySize);

            try {
                const proxyResult = Module._vsce_phe_server_generate_server_key_pair(this.ctxPtr, serverPrivateKeyCtxPtr, serverPublicKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const serverPrivateKeyPtr = Module._vsc_buffer_bytes(serverPrivateKeyCtxPtr);
                const serverPrivateKey = Module.HEAPU8.slice(serverPrivateKeyPtr, serverPrivateKeyPtr + serverPrivateKeySize);

                const serverPublicKeyPtr = Module._vsc_buffer_bytes(serverPublicKeyCtxPtr);
                const serverPublicKey = Module.HEAPU8.slice(serverPublicKeyPtr, serverPublicKeyPtr + serverPublicKeySize);
                return { serverPrivateKey, serverPublicKey };
            } finally {
                Module._vsc_buffer_delete(serverPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(serverPublicKeyCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit EnrollmentResponse
         */
        enrollmentResponseLen() {
            let proxyResult;
            proxyResult = Module._vsce_phe_server_enrollment_response_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Generates a new random enrollment and proof for a new user
         */
        getEnrollment(serverPrivateKey, serverPublicKey) {
            // assert(typeof serverPrivateKey === 'Uint8Array')
            // assert(typeof serverPublicKey === 'Uint8Array')

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
            const serverPublicKeySize = serverPublicKey.length * serverPublicKey.BYTES_PER_ELEMENT;
            const serverPublicKeyPtr = Module._malloc(serverPublicKeySize);
            Module.HEAP8.set(serverPublicKey, serverPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPublicKeyCtxPtr = Module._malloc(serverPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPublicKeyCtxPtr, serverPublicKeyPtr, serverPublicKeySize);

            const enrollmentResponseSize = PheServer.enrollmentResponseLen();
            const enrollmentResponseCtxPtr = Module._vsc_buffer_new_with_capacity(enrollmentResponseSize);

            try {
                const proxyResult = Module._vsce_phe_server_get_enrollment(this.ctxPtr, serverPrivateKeyCtxPtr, serverPublicKeyCtxPtr, enrollmentResponseCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const enrollmentResponsePtr = Module._vsc_buffer_bytes(enrollmentResponseCtxPtr);
                const enrollmentResponse = Module.HEAPU8.slice(enrollmentResponsePtr, enrollmentResponsePtr + enrollmentResponseSize);
                return enrollmentResponse;
            } finally {
                Module._free(serverPrivateKeyPtr);
                Module._free(serverPrivateKeyCtxPtr);
                Module._free(serverPublicKeyPtr);
                Module._free(serverPublicKeyCtxPtr);
                Module._vsc_buffer_delete(enrollmentResponseCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit VerifyPasswordResponse
         */
        verifyPasswordResponseLen() {
            let proxyResult;
            proxyResult = Module._vsce_phe_server_verify_password_response_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Verifies existing user's password and generates response with proof
         */
        verifyPassword(serverPrivateKey, serverPublicKey, verifyPasswordRequest) {
            // assert(typeof serverPrivateKey === 'Uint8Array')
            // assert(typeof serverPublicKey === 'Uint8Array')
            // assert(typeof verifyPasswordRequest === 'Uint8Array')

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
            const serverPublicKeySize = serverPublicKey.length * serverPublicKey.BYTES_PER_ELEMENT;
            const serverPublicKeyPtr = Module._malloc(serverPublicKeySize);
            Module.HEAP8.set(serverPublicKey, serverPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPublicKeyCtxPtr = Module._malloc(serverPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPublicKeyCtxPtr, serverPublicKeyPtr, serverPublicKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const verifyPasswordRequestSize = verifyPasswordRequest.length * verifyPasswordRequest.BYTES_PER_ELEMENT;
            const verifyPasswordRequestPtr = Module._malloc(verifyPasswordRequestSize);
            Module.HEAP8.set(verifyPasswordRequest, verifyPasswordRequestPtr);

            //  Create C structure vsc_data_t.
            const verifyPasswordRequestCtxSize = Module._vsc_data_ctx_size();
            const verifyPasswordRequestCtxPtr = Module._malloc(verifyPasswordRequestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(verifyPasswordRequestCtxPtr, verifyPasswordRequestPtr, verifyPasswordRequestSize);

            const verifyPasswordResponseSize = PheServer.verifyPasswordResponseLen();
            const verifyPasswordResponseCtxPtr = Module._vsc_buffer_new_with_capacity(verifyPasswordResponseSize);

            try {
                const proxyResult = Module._vsce_phe_server_verify_password(this.ctxPtr, serverPrivateKeyCtxPtr, serverPublicKeyCtxPtr, verifyPasswordRequestCtxPtr, verifyPasswordResponseCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const verifyPasswordResponsePtr = Module._vsc_buffer_bytes(verifyPasswordResponseCtxPtr);
                const verifyPasswordResponse = Module.HEAPU8.slice(verifyPasswordResponsePtr, verifyPasswordResponsePtr + verifyPasswordResponseSize);
                return verifyPasswordResponse;
            } finally {
                Module._free(serverPrivateKeyPtr);
                Module._free(serverPrivateKeyCtxPtr);
                Module._free(serverPublicKeyPtr);
                Module._free(serverPublicKeyCtxPtr);
                Module._free(verifyPasswordRequestPtr);
                Module._free(verifyPasswordRequestCtxPtr);
                Module._vsc_buffer_delete(verifyPasswordResponseCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit UpdateToken
         */
        updateTokenLen() {
            let proxyResult;
            proxyResult = Module._vsce_phe_server_update_token_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Updates server's private and public keys and issues an update token for use on client's side
         */
        rotateKeys(serverPrivateKey) {
            // assert(typeof serverPrivateKey === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const serverPrivateKeySize = serverPrivateKey.length * serverPrivateKey.BYTES_PER_ELEMENT;
            const serverPrivateKeyPtr = Module._malloc(serverPrivateKeySize);
            Module.HEAP8.set(serverPrivateKey, serverPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const serverPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPrivateKeyCtxPtr = Module._malloc(serverPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPrivateKeyCtxPtr, serverPrivateKeyPtr, serverPrivateKeySize);

            const newServerPrivateKeySize = PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const newServerPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPrivateKeySize);

            const newServerPublicKeySize = PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const newServerPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPublicKeySize);

            const updateTokenSize = PheServer.updateTokenLen();
            const updateTokenCtxPtr = Module._vsc_buffer_new_with_capacity(updateTokenSize);

            try {
                const proxyResult = Module._vsce_phe_server_rotate_keys(this.ctxPtr, serverPrivateKeyCtxPtr, newServerPrivateKeyCtxPtr, newServerPublicKeyCtxPtr, updateTokenCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const newServerPrivateKeyPtr = Module._vsc_buffer_bytes(newServerPrivateKeyCtxPtr);
                const newServerPrivateKey = Module.HEAPU8.slice(newServerPrivateKeyPtr, newServerPrivateKeyPtr + newServerPrivateKeySize);

                const newServerPublicKeyPtr = Module._vsc_buffer_bytes(newServerPublicKeyCtxPtr);
                const newServerPublicKey = Module.HEAPU8.slice(newServerPublicKeyPtr, newServerPublicKeyPtr + newServerPublicKeySize);

                const updateTokenPtr = Module._vsc_buffer_bytes(updateTokenCtxPtr);
                const updateToken = Module.HEAPU8.slice(updateTokenPtr, updateTokenPtr + updateTokenSize);
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

    return PheServer;
};

module.exports = initPheServer;
