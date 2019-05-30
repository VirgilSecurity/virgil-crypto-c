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


const initPythia = (Module, modules) => {
    /**
     * Provide Pythia implementation based on the Virgil Security.
     */
    class Pythia {

        /**
         * Performs global initialization of the pythia library.
         * Must be called once for entire application at startup.
         */
        static configure() {
            const proxyResult = Module._vscp_pythia_configure();
            modules.PythiaError.handleStatusCode(proxyResult);
        }

        /**
         * Performs global cleanup of the pythia library.
         * Must be called once for entire application before exit.
         */
        static cleanup() {
            Module._vscp_pythia_cleanup();
        }

        /**
         * Return length of the buffer needed to hold 'blinded password'.
         */
        static blindedPasswordBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_blinded_password_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'deblinded password'.
         */
        static deblindedPasswordBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_deblinded_password_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'blinding secret'.
         */
        static blindingSecretBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_blinding_secret_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'transformation private key'.
         */
        static transformationPrivateKeyBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_transformation_private_key_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'transformation public key'.
         */
        static transformationPublicKeyBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_transformation_public_key_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'transformed password'.
         */
        static transformedPasswordBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_transformed_password_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'transformed tweak'.
         */
        static transformedTweakBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_transformed_tweak_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'proof value'.
         */
        static proofValueBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_proof_value_buf_len();
            return proxyResult;
        }

        /**
         * Return length of the buffer needed to hold 'password update token'.
         */
        static passwordUpdateTokenBufLen() {
            let proxyResult;
            proxyResult = Module._vscp_pythia_password_update_token_buf_len();
            return proxyResult;
        }

        /**
         * Blinds password. Turns password into a pseudo-random string.
         * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
         */
        static blind(password) {
            // assert(typeof password === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);

            //  Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);

            const blindedPasswordSize = Pythia.blindedPasswordBufLen();
            const blindedPasswordCtxPtr = Module._vsc_buffer_new_with_capacity(blindedPasswordSize);

            const blindingSecretSize = Pythia.blindingSecretBufLen();
            const blindingSecretCtxPtr = Module._vsc_buffer_new_with_capacity(blindingSecretSize);

            try {
                const proxyResult = Module._vscp_pythia_blind(passwordCtxPtr, blindedPasswordCtxPtr, blindingSecretCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const blindedPasswordPtr = Module._vsc_buffer_bytes(blindedPasswordCtxPtr);
                const blindedPassword = Module.HEAPU8.slice(blindedPasswordPtr, blindedPasswordPtr + blindedPasswordSize);

                const blindingSecretPtr = Module._vsc_buffer_bytes(blindingSecretCtxPtr);
                const blindingSecret = Module.HEAPU8.slice(blindingSecretPtr, blindingSecretPtr + blindingSecretSize);
                return { blindedPassword, blindingSecret };
            } finally {
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._vsc_buffer_delete(blindedPasswordCtxPtr);
                Module._vsc_buffer_delete(blindingSecretCtxPtr);
            }
        }

        /**
         * Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
         */
        static deblind(transformedPassword, blindingSecret) {
            // assert(typeof transformedPassword === 'Uint8Array')
            // assert(typeof blindingSecret === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const transformedPasswordSize = transformedPassword.length * transformedPassword.BYTES_PER_ELEMENT;
            const transformedPasswordPtr = Module._malloc(transformedPasswordSize);
            Module.HEAP8.set(transformedPassword, transformedPasswordPtr);

            //  Create C structure vsc_data_t.
            const transformedPasswordCtxSize = Module._vsc_data_ctx_size();
            const transformedPasswordCtxPtr = Module._malloc(transformedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformedPasswordCtxPtr, transformedPasswordPtr, transformedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const blindingSecretSize = blindingSecret.length * blindingSecret.BYTES_PER_ELEMENT;
            const blindingSecretPtr = Module._malloc(blindingSecretSize);
            Module.HEAP8.set(blindingSecret, blindingSecretPtr);

            //  Create C structure vsc_data_t.
            const blindingSecretCtxSize = Module._vsc_data_ctx_size();
            const blindingSecretCtxPtr = Module._malloc(blindingSecretCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindingSecretCtxPtr, blindingSecretPtr, blindingSecretSize);

            const deblindedPasswordSize = Pythia.deblindedPasswordBufLen();
            const deblindedPasswordCtxPtr = Module._vsc_buffer_new_with_capacity(deblindedPasswordSize);

            try {
                const proxyResult = Module._vscp_pythia_deblind(transformedPasswordCtxPtr, blindingSecretCtxPtr, deblindedPasswordCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const deblindedPasswordPtr = Module._vsc_buffer_bytes(deblindedPasswordCtxPtr);
                const deblindedPassword = Module.HEAPU8.slice(deblindedPasswordPtr, deblindedPasswordPtr + deblindedPasswordSize);
                return deblindedPassword;
            } finally {
                Module._free(transformedPasswordPtr);
                Module._free(transformedPasswordCtxPtr);
                Module._free(blindingSecretPtr);
                Module._free(blindingSecretCtxPtr);
                Module._vsc_buffer_delete(deblindedPasswordCtxPtr);
            }
        }

        /**
         * Computes transformation private and public key.
         */
        static computeTransformationKeyPair(transformationKeyId, pythiaSecret, pythiaScopeSecret) {
            // assert(typeof transformationKeyId === 'Uint8Array')
            // assert(typeof pythiaSecret === 'Uint8Array')
            // assert(typeof pythiaScopeSecret === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const transformationKeyIdSize = transformationKeyId.length * transformationKeyId.BYTES_PER_ELEMENT;
            const transformationKeyIdPtr = Module._malloc(transformationKeyIdSize);
            Module.HEAP8.set(transformationKeyId, transformationKeyIdPtr);

            //  Create C structure vsc_data_t.
            const transformationKeyIdCtxSize = Module._vsc_data_ctx_size();
            const transformationKeyIdCtxPtr = Module._malloc(transformationKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformationKeyIdCtxPtr, transformationKeyIdPtr, transformationKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const pythiaSecretSize = pythiaSecret.length * pythiaSecret.BYTES_PER_ELEMENT;
            const pythiaSecretPtr = Module._malloc(pythiaSecretSize);
            Module.HEAP8.set(pythiaSecret, pythiaSecretPtr);

            //  Create C structure vsc_data_t.
            const pythiaSecretCtxSize = Module._vsc_data_ctx_size();
            const pythiaSecretCtxPtr = Module._malloc(pythiaSecretCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(pythiaSecretCtxPtr, pythiaSecretPtr, pythiaSecretSize);

            //  Copy bytes from JS memory to the WASM memory.
            const pythiaScopeSecretSize = pythiaScopeSecret.length * pythiaScopeSecret.BYTES_PER_ELEMENT;
            const pythiaScopeSecretPtr = Module._malloc(pythiaScopeSecretSize);
            Module.HEAP8.set(pythiaScopeSecret, pythiaScopeSecretPtr);

            //  Create C structure vsc_data_t.
            const pythiaScopeSecretCtxSize = Module._vsc_data_ctx_size();
            const pythiaScopeSecretCtxPtr = Module._malloc(pythiaScopeSecretCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(pythiaScopeSecretCtxPtr, pythiaScopeSecretPtr, pythiaScopeSecretSize);

            const transformationPrivateKeySize = Pythia.transformationPrivateKeyBufLen();
            const transformationPrivateKeyCtxPtr = Module._vsc_buffer_new_with_capacity(transformationPrivateKeySize);

            const transformationPublicKeySize = Pythia.transformationPublicKeyBufLen();
            const transformationPublicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(transformationPublicKeySize);

            try {
                const proxyResult = Module._vscp_pythia_compute_transformation_key_pair(transformationKeyIdCtxPtr, pythiaSecretCtxPtr, pythiaScopeSecretCtxPtr, transformationPrivateKeyCtxPtr, transformationPublicKeyCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const transformationPrivateKeyPtr = Module._vsc_buffer_bytes(transformationPrivateKeyCtxPtr);
                const transformationPrivateKey = Module.HEAPU8.slice(transformationPrivateKeyPtr, transformationPrivateKeyPtr + transformationPrivateKeySize);

                const transformationPublicKeyPtr = Module._vsc_buffer_bytes(transformationPublicKeyCtxPtr);
                const transformationPublicKey = Module.HEAPU8.slice(transformationPublicKeyPtr, transformationPublicKeyPtr + transformationPublicKeySize);
                return { transformationPrivateKey, transformationPublicKey };
            } finally {
                Module._free(transformationKeyIdPtr);
                Module._free(transformationKeyIdCtxPtr);
                Module._free(pythiaSecretPtr);
                Module._free(pythiaSecretCtxPtr);
                Module._free(pythiaScopeSecretPtr);
                Module._free(pythiaScopeSecretCtxPtr);
                Module._vsc_buffer_delete(transformationPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(transformationPublicKeyCtxPtr);
            }
        }

        /**
         * Transforms blinded password using transformation private key.
         */
        static transform(blindedPassword, tweak, transformationPrivateKey) {
            // assert(typeof blindedPassword === 'Uint8Array')
            // assert(typeof tweak === 'Uint8Array')
            // assert(typeof transformationPrivateKey === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const blindedPasswordSize = blindedPassword.length * blindedPassword.BYTES_PER_ELEMENT;
            const blindedPasswordPtr = Module._malloc(blindedPasswordSize);
            Module.HEAP8.set(blindedPassword, blindedPasswordPtr);

            //  Create C structure vsc_data_t.
            const blindedPasswordCtxSize = Module._vsc_data_ctx_size();
            const blindedPasswordCtxPtr = Module._malloc(blindedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPasswordCtxPtr, blindedPasswordPtr, blindedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const tweakSize = tweak.length * tweak.BYTES_PER_ELEMENT;
            const tweakPtr = Module._malloc(tweakSize);
            Module.HEAP8.set(tweak, tweakPtr);

            //  Create C structure vsc_data_t.
            const tweakCtxSize = Module._vsc_data_ctx_size();
            const tweakCtxPtr = Module._malloc(tweakCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(tweakCtxPtr, tweakPtr, tweakSize);

            //  Copy bytes from JS memory to the WASM memory.
            const transformationPrivateKeySize = transformationPrivateKey.length * transformationPrivateKey.BYTES_PER_ELEMENT;
            const transformationPrivateKeyPtr = Module._malloc(transformationPrivateKeySize);
            Module.HEAP8.set(transformationPrivateKey, transformationPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const transformationPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const transformationPrivateKeyCtxPtr = Module._malloc(transformationPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformationPrivateKeyCtxPtr, transformationPrivateKeyPtr, transformationPrivateKeySize);

            const transformedPasswordSize = Pythia.transformedPasswordBufLen();
            const transformedPasswordCtxPtr = Module._vsc_buffer_new_with_capacity(transformedPasswordSize);

            const transformedTweakSize = Pythia.transformedTweakBufLen();
            const transformedTweakCtxPtr = Module._vsc_buffer_new_with_capacity(transformedTweakSize);

            try {
                const proxyResult = Module._vscp_pythia_transform(blindedPasswordCtxPtr, tweakCtxPtr, transformationPrivateKeyCtxPtr, transformedPasswordCtxPtr, transformedTweakCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const transformedPasswordPtr = Module._vsc_buffer_bytes(transformedPasswordCtxPtr);
                const transformedPassword = Module.HEAPU8.slice(transformedPasswordPtr, transformedPasswordPtr + transformedPasswordSize);

                const transformedTweakPtr = Module._vsc_buffer_bytes(transformedTweakCtxPtr);
                const transformedTweak = Module.HEAPU8.slice(transformedTweakPtr, transformedTweakPtr + transformedTweakSize);
                return { transformedPassword, transformedTweak };
            } finally {
                Module._free(blindedPasswordPtr);
                Module._free(blindedPasswordCtxPtr);
                Module._free(tweakPtr);
                Module._free(tweakCtxPtr);
                Module._free(transformationPrivateKeyPtr);
                Module._free(transformationPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(transformedPasswordCtxPtr);
                Module._vsc_buffer_delete(transformedTweakCtxPtr);
            }
        }

        /**
         * Generates proof that server possesses secret values that were used to transform password.
         */
        static prove(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey, transformationPublicKey) {
            // assert(typeof transformedPassword === 'Uint8Array')
            // assert(typeof blindedPassword === 'Uint8Array')
            // assert(typeof transformedTweak === 'Uint8Array')
            // assert(typeof transformationPrivateKey === 'Uint8Array')
            // assert(typeof transformationPublicKey === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const transformedPasswordSize = transformedPassword.length * transformedPassword.BYTES_PER_ELEMENT;
            const transformedPasswordPtr = Module._malloc(transformedPasswordSize);
            Module.HEAP8.set(transformedPassword, transformedPasswordPtr);

            //  Create C structure vsc_data_t.
            const transformedPasswordCtxSize = Module._vsc_data_ctx_size();
            const transformedPasswordCtxPtr = Module._malloc(transformedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformedPasswordCtxPtr, transformedPasswordPtr, transformedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const blindedPasswordSize = blindedPassword.length * blindedPassword.BYTES_PER_ELEMENT;
            const blindedPasswordPtr = Module._malloc(blindedPasswordSize);
            Module.HEAP8.set(blindedPassword, blindedPasswordPtr);

            //  Create C structure vsc_data_t.
            const blindedPasswordCtxSize = Module._vsc_data_ctx_size();
            const blindedPasswordCtxPtr = Module._malloc(blindedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPasswordCtxPtr, blindedPasswordPtr, blindedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const transformedTweakSize = transformedTweak.length * transformedTweak.BYTES_PER_ELEMENT;
            const transformedTweakPtr = Module._malloc(transformedTweakSize);
            Module.HEAP8.set(transformedTweak, transformedTweakPtr);

            //  Create C structure vsc_data_t.
            const transformedTweakCtxSize = Module._vsc_data_ctx_size();
            const transformedTweakCtxPtr = Module._malloc(transformedTweakCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformedTweakCtxPtr, transformedTweakPtr, transformedTweakSize);

            //  Copy bytes from JS memory to the WASM memory.
            const transformationPrivateKeySize = transformationPrivateKey.length * transformationPrivateKey.BYTES_PER_ELEMENT;
            const transformationPrivateKeyPtr = Module._malloc(transformationPrivateKeySize);
            Module.HEAP8.set(transformationPrivateKey, transformationPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const transformationPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const transformationPrivateKeyCtxPtr = Module._malloc(transformationPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformationPrivateKeyCtxPtr, transformationPrivateKeyPtr, transformationPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const transformationPublicKeySize = transformationPublicKey.length * transformationPublicKey.BYTES_PER_ELEMENT;
            const transformationPublicKeyPtr = Module._malloc(transformationPublicKeySize);
            Module.HEAP8.set(transformationPublicKey, transformationPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const transformationPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const transformationPublicKeyCtxPtr = Module._malloc(transformationPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformationPublicKeyCtxPtr, transformationPublicKeyPtr, transformationPublicKeySize);

            const proofValueCSize = Pythia.proofValueBufLen();
            const proofValueCCtxPtr = Module._vsc_buffer_new_with_capacity(proofValueCSize);

            const proofValueUSize = Pythia.proofValueBufLen();
            const proofValueUCtxPtr = Module._vsc_buffer_new_with_capacity(proofValueUSize);

            try {
                const proxyResult = Module._vscp_pythia_prove(transformedPasswordCtxPtr, blindedPasswordCtxPtr, transformedTweakCtxPtr, transformationPrivateKeyCtxPtr, transformationPublicKeyCtxPtr, proofValueCCtxPtr, proofValueUCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const proofValueCPtr = Module._vsc_buffer_bytes(proofValueCCtxPtr);
                const proofValueC = Module.HEAPU8.slice(proofValueCPtr, proofValueCPtr + proofValueCSize);

                const proofValueUPtr = Module._vsc_buffer_bytes(proofValueUCtxPtr);
                const proofValueU = Module.HEAPU8.slice(proofValueUPtr, proofValueUPtr + proofValueUSize);
                return { proofValueC, proofValueU };
            } finally {
                Module._free(transformedPasswordPtr);
                Module._free(transformedPasswordCtxPtr);
                Module._free(blindedPasswordPtr);
                Module._free(blindedPasswordCtxPtr);
                Module._free(transformedTweakPtr);
                Module._free(transformedTweakCtxPtr);
                Module._free(transformationPrivateKeyPtr);
                Module._free(transformationPrivateKeyCtxPtr);
                Module._free(transformationPublicKeyPtr);
                Module._free(transformationPublicKeyCtxPtr);
                Module._vsc_buffer_delete(proofValueCCtxPtr);
                Module._vsc_buffer_delete(proofValueUCtxPtr);
            }
        }

        /**
         * This operation allows client to verify that the output of transform() is correct,
         * assuming that client has previously stored transformation public key.
         */
        static verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU) {
            // assert(typeof transformedPassword === 'Uint8Array')
            // assert(typeof blindedPassword === 'Uint8Array')
            // assert(typeof tweak === 'Uint8Array')
            // assert(typeof transformationPublicKey === 'Uint8Array')
            // assert(typeof proofValueC === 'Uint8Array')
            // assert(typeof proofValueU === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const transformedPasswordSize = transformedPassword.length * transformedPassword.BYTES_PER_ELEMENT;
            const transformedPasswordPtr = Module._malloc(transformedPasswordSize);
            Module.HEAP8.set(transformedPassword, transformedPasswordPtr);

            //  Create C structure vsc_data_t.
            const transformedPasswordCtxSize = Module._vsc_data_ctx_size();
            const transformedPasswordCtxPtr = Module._malloc(transformedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformedPasswordCtxPtr, transformedPasswordPtr, transformedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const blindedPasswordSize = blindedPassword.length * blindedPassword.BYTES_PER_ELEMENT;
            const blindedPasswordPtr = Module._malloc(blindedPasswordSize);
            Module.HEAP8.set(blindedPassword, blindedPasswordPtr);

            //  Create C structure vsc_data_t.
            const blindedPasswordCtxSize = Module._vsc_data_ctx_size();
            const blindedPasswordCtxPtr = Module._malloc(blindedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPasswordCtxPtr, blindedPasswordPtr, blindedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const tweakSize = tweak.length * tweak.BYTES_PER_ELEMENT;
            const tweakPtr = Module._malloc(tweakSize);
            Module.HEAP8.set(tweak, tweakPtr);

            //  Create C structure vsc_data_t.
            const tweakCtxSize = Module._vsc_data_ctx_size();
            const tweakCtxPtr = Module._malloc(tweakCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(tweakCtxPtr, tweakPtr, tweakSize);

            //  Copy bytes from JS memory to the WASM memory.
            const transformationPublicKeySize = transformationPublicKey.length * transformationPublicKey.BYTES_PER_ELEMENT;
            const transformationPublicKeyPtr = Module._malloc(transformationPublicKeySize);
            Module.HEAP8.set(transformationPublicKey, transformationPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const transformationPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const transformationPublicKeyCtxPtr = Module._malloc(transformationPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(transformationPublicKeyCtxPtr, transformationPublicKeyPtr, transformationPublicKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const proofValueCSize = proofValueC.length * proofValueC.BYTES_PER_ELEMENT;
            const proofValueCPtr = Module._malloc(proofValueCSize);
            Module.HEAP8.set(proofValueC, proofValueCPtr);

            //  Create C structure vsc_data_t.
            const proofValueCCtxSize = Module._vsc_data_ctx_size();
            const proofValueCCtxPtr = Module._malloc(proofValueCCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(proofValueCCtxPtr, proofValueCPtr, proofValueCSize);

            //  Copy bytes from JS memory to the WASM memory.
            const proofValueUSize = proofValueU.length * proofValueU.BYTES_PER_ELEMENT;
            const proofValueUPtr = Module._malloc(proofValueUSize);
            Module.HEAP8.set(proofValueU, proofValueUPtr);

            //  Create C structure vsc_data_t.
            const proofValueUCtxSize = Module._vsc_data_ctx_size();
            const proofValueUCtxPtr = Module._malloc(proofValueUCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(proofValueUCtxPtr, proofValueUPtr, proofValueUSize);

            const errorCtxSize = Module._vscp_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscp_pythia_verify(transformedPasswordCtxPtr, blindedPasswordCtxPtr, tweakCtxPtr, transformationPublicKeyCtxPtr, proofValueCCtxPtr, proofValueUCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscp_error_status(errorCtxPtr);
                modules.PythiaError.handleStatusCode(errorStatus);

                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(transformedPasswordPtr);
                Module._free(transformedPasswordCtxPtr);
                Module._free(blindedPasswordPtr);
                Module._free(blindedPasswordCtxPtr);
                Module._free(tweakPtr);
                Module._free(tweakCtxPtr);
                Module._free(transformationPublicKeyPtr);
                Module._free(transformationPublicKeyCtxPtr);
                Module._free(proofValueCPtr);
                Module._free(proofValueCCtxPtr);
                Module._free(proofValueUPtr);
                Module._free(proofValueUCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Rotates old transformation key to new transformation key and generates 'password update token',
         * that can update 'deblinded password'(s).
         *
         * This action should increment version of the 'pythia scope secret'.
         */
        static getPasswordUpdateToken(previousTransformationPrivateKey, newTransformationPrivateKey) {
            // assert(typeof previousTransformationPrivateKey === 'Uint8Array')
            // assert(typeof newTransformationPrivateKey === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const previousTransformationPrivateKeySize = previousTransformationPrivateKey.length * previousTransformationPrivateKey.BYTES_PER_ELEMENT;
            const previousTransformationPrivateKeyPtr = Module._malloc(previousTransformationPrivateKeySize);
            Module.HEAP8.set(previousTransformationPrivateKey, previousTransformationPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const previousTransformationPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const previousTransformationPrivateKeyCtxPtr = Module._malloc(previousTransformationPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(previousTransformationPrivateKeyCtxPtr, previousTransformationPrivateKeyPtr, previousTransformationPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const newTransformationPrivateKeySize = newTransformationPrivateKey.length * newTransformationPrivateKey.BYTES_PER_ELEMENT;
            const newTransformationPrivateKeyPtr = Module._malloc(newTransformationPrivateKeySize);
            Module.HEAP8.set(newTransformationPrivateKey, newTransformationPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const newTransformationPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const newTransformationPrivateKeyCtxPtr = Module._malloc(newTransformationPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(newTransformationPrivateKeyCtxPtr, newTransformationPrivateKeyPtr, newTransformationPrivateKeySize);

            const passwordUpdateTokenSize = Pythia.passwordUpdateTokenBufLen();
            const passwordUpdateTokenCtxPtr = Module._vsc_buffer_new_with_capacity(passwordUpdateTokenSize);

            try {
                const proxyResult = Module._vscp_pythia_get_password_update_token(previousTransformationPrivateKeyCtxPtr, newTransformationPrivateKeyCtxPtr, passwordUpdateTokenCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const passwordUpdateTokenPtr = Module._vsc_buffer_bytes(passwordUpdateTokenCtxPtr);
                const passwordUpdateToken = Module.HEAPU8.slice(passwordUpdateTokenPtr, passwordUpdateTokenPtr + passwordUpdateTokenSize);
                return passwordUpdateToken;
            } finally {
                Module._free(previousTransformationPrivateKeyPtr);
                Module._free(previousTransformationPrivateKeyCtxPtr);
                Module._free(newTransformationPrivateKeyPtr);
                Module._free(newTransformationPrivateKeyCtxPtr);
                Module._vsc_buffer_delete(passwordUpdateTokenCtxPtr);
            }
        }

        /**
         * Updates previously stored 'deblinded password' with 'password update token'.
         * After this call, 'transform()' called with new arguments will return corresponding values.
         */
        static updateDeblindedWithToken(deblindedPassword, passwordUpdateToken) {
            // assert(typeof deblindedPassword === 'Uint8Array')
            // assert(typeof passwordUpdateToken === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const deblindedPasswordSize = deblindedPassword.length * deblindedPassword.BYTES_PER_ELEMENT;
            const deblindedPasswordPtr = Module._malloc(deblindedPasswordSize);
            Module.HEAP8.set(deblindedPassword, deblindedPasswordPtr);

            //  Create C structure vsc_data_t.
            const deblindedPasswordCtxSize = Module._vsc_data_ctx_size();
            const deblindedPasswordCtxPtr = Module._malloc(deblindedPasswordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(deblindedPasswordCtxPtr, deblindedPasswordPtr, deblindedPasswordSize);

            //  Copy bytes from JS memory to the WASM memory.
            const passwordUpdateTokenSize = passwordUpdateToken.length * passwordUpdateToken.BYTES_PER_ELEMENT;
            const passwordUpdateTokenPtr = Module._malloc(passwordUpdateTokenSize);
            Module.HEAP8.set(passwordUpdateToken, passwordUpdateTokenPtr);

            //  Create C structure vsc_data_t.
            const passwordUpdateTokenCtxSize = Module._vsc_data_ctx_size();
            const passwordUpdateTokenCtxPtr = Module._malloc(passwordUpdateTokenCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordUpdateTokenCtxPtr, passwordUpdateTokenPtr, passwordUpdateTokenSize);

            const updatedDeblindedPasswordSize = Pythia.deblindedPasswordBufLen();
            const updatedDeblindedPasswordCtxPtr = Module._vsc_buffer_new_with_capacity(updatedDeblindedPasswordSize);

            try {
                const proxyResult = Module._vscp_pythia_update_deblinded_with_token(deblindedPasswordCtxPtr, passwordUpdateTokenCtxPtr, updatedDeblindedPasswordCtxPtr);
                modules.PythiaError.handleStatusCode(proxyResult);

                const updatedDeblindedPasswordPtr = Module._vsc_buffer_bytes(updatedDeblindedPasswordCtxPtr);
                const updatedDeblindedPassword = Module.HEAPU8.slice(updatedDeblindedPasswordPtr, updatedDeblindedPasswordPtr + updatedDeblindedPasswordSize);
                return updatedDeblindedPassword;
            } finally {
                Module._free(deblindedPasswordPtr);
                Module._free(deblindedPasswordCtxPtr);
                Module._free(passwordUpdateTokenPtr);
                Module._free(passwordUpdateTokenCtxPtr);
                Module._vsc_buffer_delete(updatedDeblindedPasswordCtxPtr);
            }
        }
    }

    return Pythia;
};

module.exports = initPythia;
