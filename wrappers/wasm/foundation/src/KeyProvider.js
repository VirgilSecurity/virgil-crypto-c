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

const initKeyProvider = (Module, modules) => {
    /**
     * Provide functionality for private key generation and importing that
     * relies on the software default implementations.
     */
    class KeyProvider {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'KeyProvider';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_key_provider_new();
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
            return new KeyProvider(Module._vscf_key_provider_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyProvider(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_key_provider_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            Module._vscf_key_provider_release_random(this.ctxPtr)
            Module._vscf_key_provider_use_random(this.ctxPtr, random.ctxPtr)
        }

        set ecies(ecies) {
            Module._vscf_key_provider_release_ecies(this.ctxPtr)
            Module._vscf_key_provider_use_ecies(this.ctxPtr, ecies.ctxPtr)
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            const proxyResult = Module._vscf_key_provider_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Setup parameters that is used during RSA key generation.
         */
        setRsaParams(bitlen) {
            // assert(typeof bitlen === 'number')
            Module._vscf_key_provider_set_rsa_params(this.ctxPtr, bitlen);
        }

        /**
         * Generate new private key from the given id.
         */
        generatePrivateKey(algId) {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_provider_generate_private_key(this.ctxPtr, algId, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Import private key from the PKCS#8 format.
         */
        importPrivateKey(keyData) {
            // assert(typeof keyData === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keyDataSize = keyData.length * keyData.BYTES_PER_ELEMENT;
            const keyDataPtr = Module._malloc(keyDataSize);
            Module.HEAP8.set(keyData, keyDataPtr);

            //  Create C structure vsc_data_t.
            const keyDataCtxSize = Module._vsc_data_ctx_size();
            const keyDataCtxPtr = Module._malloc(keyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyDataCtxPtr, keyDataPtr, keyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_provider_import_private_key(this.ctxPtr, keyDataCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(keyDataPtr);
                Module._free(keyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Import public key from the PKCS#8 format.
         */
        importPublicKey(keyData) {
            // assert(typeof keyData === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keyDataSize = keyData.length * keyData.BYTES_PER_ELEMENT;
            const keyDataPtr = Module._malloc(keyDataSize);
            Module.HEAP8.set(keyData, keyDataPtr);

            //  Create C structure vsc_data_t.
            const keyDataCtxSize = Module._vsc_data_ctx_size();
            const keyDataCtxPtr = Module._malloc(keyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyDataCtxPtr, keyDataPtr, keyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_provider_import_public_key(this.ctxPtr, keyDataCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(keyDataPtr);
                Module._free(keyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Calculate buffer size enough to hold exported public key.
         *
         * Precondition: public key must be exportable.
         */
        exportedPublicKeyLen(publicKey) {
            let proxyResult;
            proxyResult = Module._vscf_key_provider_exported_public_key_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Export given public key to the PKCS#8 DER format.
         *
         * Precondition: public key must be exportable.
         */
        exportPublicKey(publicKey) {
            const outCapacity = this.exportedPublicKeyLen(publicKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_key_provider_export_public_key(this.ctxPtr, publicKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Calculate buffer size enough to hold exported private key.
         *
         * Precondition: private key must be exportable.
         */
        exportedPrivateKeyLen(privateKey) {
            let proxyResult;
            proxyResult = Module._vscf_key_provider_exported_private_key_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Export given private key to the PKCS#8 or SEC1 DER format.
         *
         * Precondition: private key must be exportable.
         */
        exportPrivateKey(privateKey) {
            const outCapacity = this.exportedPrivateKeyLen(privateKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_key_provider_export_private_key(this.ctxPtr, privateKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }
    }

    return KeyProvider;
};

module.exports = initKeyProvider;
