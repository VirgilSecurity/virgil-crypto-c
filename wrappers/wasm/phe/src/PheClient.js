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


const initPheClient = (Module, modules) => {
    /**
     * Class for client-side PHE crypto operations.
     * This class is thread-safe in case if VSCE_MULTI_THREAD defined
     */
    class PheClient {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PheClient';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_phe_client_new();
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
            return new PheClient(Module._vsce_phe_client_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PheClient(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_phe_client_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            Module._vsce_phe_client_release_random(this.ctxPtr)
            Module._vsce_phe_client_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            Module._vsce_phe_client_release_operation_random(this.ctxPtr)
            Module._vsce_phe_client_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        setupDefaults() {
            const proxyResult = Module._vsce_phe_client_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        /**
         * Sets client private and server public key
         * Call this method before any other methods except `update enrollment record` and `generate client private key`
         * This function should be called only once
         */
        setKeys(clientPrivateKey, serverPublicKey) {
            // assert(typeof clientPrivateKey === 'Uint8Array')
            // assert(typeof serverPublicKey === 'Uint8Array')

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
                const proxyResult = Module._vsce_phe_client_set_keys(this.ctxPtr, clientPrivateKeyCtxPtr, serverPublicKeyCtxPtr);
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
            const clientPrivateKeySize = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const clientPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(clientPrivateKeySize);

            try {
                const proxyResult = Module._vsce_phe_client_generate_client_private_key(this.ctxPtr, clientPrivateKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const clientPrivateKeyPtr = Module._vsc_buffer_bytes(clientPrivateKeyCtxPtr);
                const clientPrivateKey = Module.HEAPU8.slice(clientPrivateKeyPtr, clientPrivateKeyPtr + clientPrivateKeySize);
                return clientPrivateKey;
            } finally {
                Module._vsc_buffer_delete(clientPrivateKeyCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit EnrollmentRecord
         */
        enrollmentRecordLen() {
            let proxyResult;
            proxyResult = Module._vsce_phe_client_enrollment_record_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
         * a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
         * Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
         */
        enrollAccount(enrollmentResponse, password) {
            // assert(typeof enrollmentResponse === 'Uint8Array')
            // assert(typeof password === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const enrollmentResponseSize = enrollmentResponse.length * enrollmentResponse.BYTES_PER_ELEMENT;
            const enrollmentResponsePtr = Module._malloc(enrollmentResponseSize);
            Module.HEAP8.set(enrollmentResponse, enrollmentResponsePtr);

            //  Create C structure vsc_data_t.
            const enrollmentResponseCtxSize = Module._vsc_data_ctx_size();
            const enrollmentResponseCtxPtr = Module._malloc(enrollmentResponseCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(enrollmentResponseCtxPtr, enrollmentResponsePtr, enrollmentResponseSize);

            //  Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);

            //  Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);

            const enrollmentRecordSize = this.enrollmentRecordLen();
            const enrollmentRecordCtxPtr = Module._vsc_buffer_new_with_capacity(enrollmentRecordSize);

            const accountKeySize = modules.PheCommon.PHE_ACCOUNT_KEY_LENGTH;
            const accountKeyCtxPtr = Module._vsc_buffer_new_with_capacity(accountKeySize);

            try {
                const proxyResult = Module._vsce_phe_client_enroll_account(this.ctxPtr, enrollmentResponseCtxPtr, passwordCtxPtr, enrollmentRecordCtxPtr, accountKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const enrollmentRecordPtr = Module._vsc_buffer_bytes(enrollmentRecordCtxPtr);
                const enrollmentRecord = Module.HEAPU8.slice(enrollmentRecordPtr, enrollmentRecordPtr + enrollmentRecordSize);

                const accountKeyPtr = Module._vsc_buffer_bytes(accountKeyCtxPtr);
                const accountKey = Module.HEAPU8.slice(accountKeyPtr, accountKeyPtr + accountKeySize);
                return { enrollmentRecord, accountKey };
            } finally {
                Module._free(enrollmentResponsePtr);
                Module._free(enrollmentResponseCtxPtr);
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._vsc_buffer_delete(enrollmentRecordCtxPtr);
                Module._vsc_buffer_delete(accountKeyCtxPtr);
            }
        }

        /**
         * Buffer size needed to fit VerifyPasswordRequest
         */
        verifyPasswordRequestLen() {
            let proxyResult;
            proxyResult = Module._vsce_phe_client_verify_password_request_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Creates a request for further password verification at the PHE server side.
         */
        createVerifyPasswordRequest(password, enrollmentRecord) {
            // assert(typeof password === 'Uint8Array')
            // assert(typeof enrollmentRecord === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);

            //  Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const enrollmentRecordSize = enrollmentRecord.length * enrollmentRecord.BYTES_PER_ELEMENT;
            const enrollmentRecordPtr = Module._malloc(enrollmentRecordSize);
            Module.HEAP8.set(enrollmentRecord, enrollmentRecordPtr);

            //  Create C structure vsc_data_t.
            const enrollmentRecordCtxSize = Module._vsc_data_ctx_size();
            const enrollmentRecordCtxPtr = Module._malloc(enrollmentRecordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(enrollmentRecordCtxPtr, enrollmentRecordPtr, enrollmentRecordSize);

            const verifyPasswordRequestSize = this.verifyPasswordRequestLen();
            const verifyPasswordRequestCtxPtr = Module._vsc_buffer_new_with_capacity(verifyPasswordRequestSize);

            try {
                const proxyResult = Module._vsce_phe_client_create_verify_password_request(this.ctxPtr, passwordCtxPtr, enrollmentRecordCtxPtr, verifyPasswordRequestCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const verifyPasswordRequestPtr = Module._vsc_buffer_bytes(verifyPasswordRequestCtxPtr);
                const verifyPasswordRequest = Module.HEAPU8.slice(verifyPasswordRequestPtr, verifyPasswordRequestPtr + verifyPasswordRequestSize);
                return verifyPasswordRequest;
            } finally {
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._free(enrollmentRecordPtr);
                Module._free(enrollmentRecordCtxPtr);
                Module._vsc_buffer_delete(verifyPasswordRequestCtxPtr);
            }
        }

        /**
         * Verifies PHE server's answer
         * If login succeeded, extracts account key
         * If login failed account key will be empty
         */
        checkResponseAndDecrypt(password, enrollmentRecord, verifyPasswordResponse) {
            // assert(typeof password === 'Uint8Array')
            // assert(typeof enrollmentRecord === 'Uint8Array')
            // assert(typeof verifyPasswordResponse === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);

            //  Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const enrollmentRecordSize = enrollmentRecord.length * enrollmentRecord.BYTES_PER_ELEMENT;
            const enrollmentRecordPtr = Module._malloc(enrollmentRecordSize);
            Module.HEAP8.set(enrollmentRecord, enrollmentRecordPtr);

            //  Create C structure vsc_data_t.
            const enrollmentRecordCtxSize = Module._vsc_data_ctx_size();
            const enrollmentRecordCtxPtr = Module._malloc(enrollmentRecordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(enrollmentRecordCtxPtr, enrollmentRecordPtr, enrollmentRecordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const verifyPasswordResponseSize = verifyPasswordResponse.length * verifyPasswordResponse.BYTES_PER_ELEMENT;
            const verifyPasswordResponsePtr = Module._malloc(verifyPasswordResponseSize);
            Module.HEAP8.set(verifyPasswordResponse, verifyPasswordResponsePtr);

            //  Create C structure vsc_data_t.
            const verifyPasswordResponseCtxSize = Module._vsc_data_ctx_size();
            const verifyPasswordResponseCtxPtr = Module._malloc(verifyPasswordResponseCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(verifyPasswordResponseCtxPtr, verifyPasswordResponsePtr, verifyPasswordResponseSize);

            const accountKeySize = modules.PheCommon.PHE_ACCOUNT_KEY_LENGTH;
            const accountKeyCtxPtr = Module._vsc_buffer_new_with_capacity(accountKeySize);

            try {
                const proxyResult = Module._vsce_phe_client_check_response_and_decrypt(this.ctxPtr, passwordCtxPtr, enrollmentRecordCtxPtr, verifyPasswordResponseCtxPtr, accountKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const accountKeyPtr = Module._vsc_buffer_bytes(accountKeyCtxPtr);
                const accountKey = Module.HEAPU8.slice(accountKeyPtr, accountKeyPtr + accountKeySize);
                return accountKey;
            } finally {
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._free(enrollmentRecordPtr);
                Module._free(enrollmentRecordCtxPtr);
                Module._free(verifyPasswordResponsePtr);
                Module._free(verifyPasswordResponseCtxPtr);
                Module._vsc_buffer_delete(accountKeyCtxPtr);
            }
        }

        /**
         * Updates client's private key and server's public key using server's update token
         * Use output values to instantiate new client instance with new keys
         */
        rotateKeys(updateToken) {
            // assert(typeof updateToken === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const updateTokenSize = updateToken.length * updateToken.BYTES_PER_ELEMENT;
            const updateTokenPtr = Module._malloc(updateTokenSize);
            Module.HEAP8.set(updateToken, updateTokenPtr);

            //  Create C structure vsc_data_t.
            const updateTokenCtxSize = Module._vsc_data_ctx_size();
            const updateTokenCtxPtr = Module._malloc(updateTokenCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(updateTokenCtxPtr, updateTokenPtr, updateTokenSize);

            const newClientPrivateKeySize = modules.PheCommon.PHE_PRIVATE_KEY_LENGTH;
            const newClientPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newClientPrivateKeySize);

            const newServerPublicKeySize = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const newServerPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(newServerPublicKeySize);

            try {
                const proxyResult = Module._vsce_phe_client_rotate_keys(this.ctxPtr, updateTokenCtxPtr, newClientPrivateKeyCtxPtr, newServerPublicKeyCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const newClientPrivateKeyPtr = Module._vsc_buffer_bytes(newClientPrivateKeyCtxPtr);
                const newClientPrivateKey = Module.HEAPU8.slice(newClientPrivateKeyPtr, newClientPrivateKeyPtr + newClientPrivateKeySize);

                const newServerPublicKeyPtr = Module._vsc_buffer_bytes(newServerPublicKeyCtxPtr);
                const newServerPublicKey = Module.HEAPU8.slice(newServerPublicKeyPtr, newServerPublicKeyPtr + newServerPublicKeySize);
                return { newClientPrivateKey, newServerPublicKey };
            } finally {
                Module._free(updateTokenPtr);
                Module._free(updateTokenCtxPtr);
                Module._vsc_buffer_delete(newClientPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(newServerPublicKeyCtxPtr);
            }
        }

        /**
         * Updates EnrollmentRecord using server's update token
         */
        updateEnrollmentRecord(enrollmentRecord, updateToken) {
            // assert(typeof enrollmentRecord === 'Uint8Array')
            // assert(typeof updateToken === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const enrollmentRecordSize = enrollmentRecord.length * enrollmentRecord.BYTES_PER_ELEMENT;
            const enrollmentRecordPtr = Module._malloc(enrollmentRecordSize);
            Module.HEAP8.set(enrollmentRecord, enrollmentRecordPtr);

            //  Create C structure vsc_data_t.
            const enrollmentRecordCtxSize = Module._vsc_data_ctx_size();
            const enrollmentRecordCtxPtr = Module._malloc(enrollmentRecordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(enrollmentRecordCtxPtr, enrollmentRecordPtr, enrollmentRecordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const updateTokenSize = updateToken.length * updateToken.BYTES_PER_ELEMENT;
            const updateTokenPtr = Module._malloc(updateTokenSize);
            Module.HEAP8.set(updateToken, updateTokenPtr);

            //  Create C structure vsc_data_t.
            const updateTokenCtxSize = Module._vsc_data_ctx_size();
            const updateTokenCtxPtr = Module._malloc(updateTokenCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(updateTokenCtxPtr, updateTokenPtr, updateTokenSize);

            const newEnrollmentRecordSize = this.enrollmentRecordLen();
            const newEnrollmentRecordCtxPtr = Module._vsc_buffer_new_with_capacity(newEnrollmentRecordSize);

            try {
                const proxyResult = Module._vsce_phe_client_update_enrollment_record(this.ctxPtr, enrollmentRecordCtxPtr, updateTokenCtxPtr, newEnrollmentRecordCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);

                const newEnrollmentRecordPtr = Module._vsc_buffer_bytes(newEnrollmentRecordCtxPtr);
                const newEnrollmentRecord = Module.HEAPU8.slice(newEnrollmentRecordPtr, newEnrollmentRecordPtr + newEnrollmentRecordSize);
                return newEnrollmentRecord;
            } finally {
                Module._free(enrollmentRecordPtr);
                Module._free(enrollmentRecordCtxPtr);
                Module._free(updateTokenPtr);
                Module._free(updateTokenCtxPtr);
                Module._vsc_buffer_delete(newEnrollmentRecordCtxPtr);
            }
        }
    }

    return PheClient;
};

module.exports = initPheClient;
