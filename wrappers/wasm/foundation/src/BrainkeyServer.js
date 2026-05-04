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

const initBrainkeyServer = (Module, modules) => {
    class BrainkeyServer {

        constructor(ctxPtr) {
            this.name = 'BrainkeyServer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_brainkey_server_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyServer(Module._vscf_brainkey_server_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyServer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_brainkey_server_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_server_release_random(this.ctxPtr)
            Module._vscf_brainkey_server_use_random(this.ctxPtr, random.ctxPtr)
        }

        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_server_release_operation_random(this.ctxPtr)
            Module._vscf_brainkey_server_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        static get POINT_LEN() {
            return 65;
        }

        get POINT_LEN() {
            return 65;
        }

        static get MPI_LEN() {
            return 32;
        }

        get MPI_LEN() {
            return 32;
        }

        static get PROOF_VALUE_LEN() {
            return 32;
        }

        get PROOF_VALUE_LEN() {
            return 32;
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_brainkey_server_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateIdentitySecret() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const identitySecretCapacity = this.MPI_LEN;
            const identitySecretCtxPtr = Module._vsc_buffer_new_with_capacity(identitySecretCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_server_generate_identity_secret(this.ctxPtr, identitySecretCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const identitySecretPtr = Module._vsc_buffer_bytes(identitySecretCtxPtr);
                const identitySecretPtrLen = Module._vsc_buffer_len(identitySecretCtxPtr);
                const identitySecret = Module.HEAPU8.slice(identitySecretPtr, identitySecretPtr + identitySecretPtrLen);
                return identitySecret;
            } finally {
                Module._vsc_buffer_delete(identitySecretCtxPtr);
            }
        }

        harden(identitySecret, blindedPoint) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('identitySecret', identitySecret);
            precondition.ensureByteArray('blindedPoint', blindedPoint);
            
            // Copy bytes from JS memory to the WASM memory.
            const identitySecretSize = identitySecret.length * identitySecret.BYTES_PER_ELEMENT;
            const identitySecretPtr = Module._malloc(identitySecretSize);
            Module.HEAP8.set(identitySecret, identitySecretPtr);
            
            // Create C structure vsc_data_t.
            const identitySecretCtxSize = Module._vsc_data_ctx_size();
            const identitySecretCtxPtr = Module._malloc(identitySecretCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(identitySecretCtxPtr, identitySecretPtr, identitySecretSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const blindedPointSize = blindedPoint.length * blindedPoint.BYTES_PER_ELEMENT;
            const blindedPointPtr = Module._malloc(blindedPointSize);
            Module.HEAP8.set(blindedPoint, blindedPointPtr);
            
            // Create C structure vsc_data_t.
            const blindedPointCtxSize = Module._vsc_data_ctx_size();
            const blindedPointCtxPtr = Module._malloc(blindedPointCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPointCtxPtr, blindedPointPtr, blindedPointSize);
            
            const hardenedPointCapacity = this.POINT_LEN;
            const hardenedPointCtxPtr = Module._vsc_buffer_new_with_capacity(hardenedPointCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_server_harden(this.ctxPtr, identitySecretCtxPtr, blindedPointCtxPtr, hardenedPointCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const hardenedPointPtr = Module._vsc_buffer_bytes(hardenedPointCtxPtr);
                const hardenedPointPtrLen = Module._vsc_buffer_len(hardenedPointCtxPtr);
                const hardenedPoint = Module.HEAPU8.slice(hardenedPointPtr, hardenedPointPtr + hardenedPointPtrLen);
                return hardenedPoint;
            } finally {
                Module._free(identitySecretPtr);
                Module._free(identitySecretCtxPtr);
                Module._free(blindedPointPtr);
                Module._free(blindedPointCtxPtr);
                Module._vsc_buffer_delete(hardenedPointCtxPtr);
            }
        }

        computePublicKey(identitySecret) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('identitySecret', identitySecret);
            
            // Copy bytes from JS memory to the WASM memory.
            const identitySecretSize = identitySecret.length * identitySecret.BYTES_PER_ELEMENT;
            const identitySecretPtr = Module._malloc(identitySecretSize);
            Module.HEAP8.set(identitySecret, identitySecretPtr);
            
            // Create C structure vsc_data_t.
            const identitySecretCtxSize = Module._vsc_data_ctx_size();
            const identitySecretCtxPtr = Module._malloc(identitySecretCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(identitySecretCtxPtr, identitySecretPtr, identitySecretSize);
            
            const publicKeyCapacity = this.POINT_LEN;
            const publicKeyCtxPtr = Module._vsc_buffer_new_with_capacity(publicKeyCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_server_compute_public_key(this.ctxPtr, identitySecretCtxPtr, publicKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const publicKeyPtr = Module._vsc_buffer_bytes(publicKeyCtxPtr);
                const publicKeyPtrLen = Module._vsc_buffer_len(publicKeyCtxPtr);
                const publicKey = Module.HEAPU8.slice(publicKeyPtr, publicKeyPtr + publicKeyPtrLen);
                return publicKey;
            } finally {
                Module._free(identitySecretPtr);
                Module._free(identitySecretCtxPtr);
                Module._vsc_buffer_delete(publicKeyCtxPtr);
            }
        }

        prove(blindedPoint, hardenedPoint, identitySecret, serverPublicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('blindedPoint', blindedPoint);
            precondition.ensureByteArray('hardenedPoint', hardenedPoint);
            precondition.ensureByteArray('identitySecret', identitySecret);
            precondition.ensureByteArray('serverPublicKey', serverPublicKey);
            
            // Copy bytes from JS memory to the WASM memory.
            const blindedPointSize = blindedPoint.length * blindedPoint.BYTES_PER_ELEMENT;
            const blindedPointPtr = Module._malloc(blindedPointSize);
            Module.HEAP8.set(blindedPoint, blindedPointPtr);
            
            // Create C structure vsc_data_t.
            const blindedPointCtxSize = Module._vsc_data_ctx_size();
            const blindedPointCtxPtr = Module._malloc(blindedPointCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPointCtxPtr, blindedPointPtr, blindedPointSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const hardenedPointSize = hardenedPoint.length * hardenedPoint.BYTES_PER_ELEMENT;
            const hardenedPointPtr = Module._malloc(hardenedPointSize);
            Module.HEAP8.set(hardenedPoint, hardenedPointPtr);
            
            // Create C structure vsc_data_t.
            const hardenedPointCtxSize = Module._vsc_data_ctx_size();
            const hardenedPointCtxPtr = Module._malloc(hardenedPointCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(hardenedPointCtxPtr, hardenedPointPtr, hardenedPointSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const identitySecretSize = identitySecret.length * identitySecret.BYTES_PER_ELEMENT;
            const identitySecretPtr = Module._malloc(identitySecretSize);
            Module.HEAP8.set(identitySecret, identitySecretPtr);
            
            // Create C structure vsc_data_t.
            const identitySecretCtxSize = Module._vsc_data_ctx_size();
            const identitySecretCtxPtr = Module._malloc(identitySecretCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(identitySecretCtxPtr, identitySecretPtr, identitySecretSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const serverPublicKeySize = serverPublicKey.length * serverPublicKey.BYTES_PER_ELEMENT;
            const serverPublicKeyPtr = Module._malloc(serverPublicKeySize);
            Module.HEAP8.set(serverPublicKey, serverPublicKeyPtr);
            
            // Create C structure vsc_data_t.
            const serverPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPublicKeyCtxPtr = Module._malloc(serverPublicKeyCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPublicKeyCtxPtr, serverPublicKeyPtr, serverPublicKeySize);
            
            const proofValueCCapacity = this.PROOF_VALUE_LEN;
            const proofValueCCtxPtr = Module._vsc_buffer_new_with_capacity(proofValueCCapacity);
            
            const proofValueSCapacity = this.PROOF_VALUE_LEN;
            const proofValueSCtxPtr = Module._vsc_buffer_new_with_capacity(proofValueSCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_server_prove(this.ctxPtr, blindedPointCtxPtr, hardenedPointCtxPtr, identitySecretCtxPtr, serverPublicKeyCtxPtr, proofValueCCtxPtr, proofValueSCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const proofValueCPtr = Module._vsc_buffer_bytes(proofValueCCtxPtr);
                const proofValueCPtrLen = Module._vsc_buffer_len(proofValueCCtxPtr);
                const proofValueC = Module.HEAPU8.slice(proofValueCPtr, proofValueCPtr + proofValueCPtrLen);
            
                const proofValueSPtr = Module._vsc_buffer_bytes(proofValueSCtxPtr);
                const proofValueSPtrLen = Module._vsc_buffer_len(proofValueSCtxPtr);
                const proofValueS = Module.HEAPU8.slice(proofValueSPtr, proofValueSPtr + proofValueSPtrLen);
                return { proofValueC, proofValueS };
            } finally {
                Module._free(blindedPointPtr);
                Module._free(blindedPointCtxPtr);
                Module._free(hardenedPointPtr);
                Module._free(hardenedPointCtxPtr);
                Module._free(identitySecretPtr);
                Module._free(identitySecretCtxPtr);
                Module._free(serverPublicKeyPtr);
                Module._free(serverPublicKeyCtxPtr);
                Module._vsc_buffer_delete(proofValueCCtxPtr);
                Module._vsc_buffer_delete(proofValueSCtxPtr);
            }
        }

    }

    return BrainkeyServer;
};

module.exports = initBrainkeyServer;
