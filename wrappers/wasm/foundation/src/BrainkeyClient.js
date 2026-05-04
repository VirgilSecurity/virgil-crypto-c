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

const initBrainkeyClient = (Module, modules) => {
    class BrainkeyClient {

        constructor(ctxPtr) {
            this.name = 'BrainkeyClient';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_brainkey_client_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyClient(Module._vscf_brainkey_client_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyClient(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_brainkey_client_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_client_release_random(this.ctxPtr)
            Module._vscf_brainkey_client_use_random(this.ctxPtr, random.ctxPtr)
        }

        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_client_release_operation_random(this.ctxPtr)
            Module._vscf_brainkey_client_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
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

        static get SEED_LEN() {
            return 32;
        }

        get SEED_LEN() {
            return 32;
        }

        static get MAX_PASSWORD_LEN() {
            return 128;
        }

        get MAX_PASSWORD_LEN() {
            return 128;
        }

        static get MAX_KEY_NAME_LEN() {
            return 128;
        }

        get MAX_KEY_NAME_LEN() {
            return 128;
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_brainkey_client_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        blind(password) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('password', password);
            
            // Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);
            
            // Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);
            
            const deblindFactorCapacity = this.MPI_LEN;
            const deblindFactorCtxPtr = Module._vsc_buffer_new_with_capacity(deblindFactorCapacity);
            
            const blindedPointCapacity = this.POINT_LEN;
            const blindedPointCtxPtr = Module._vsc_buffer_new_with_capacity(blindedPointCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_client_blind(this.ctxPtr, passwordCtxPtr, deblindFactorCtxPtr, blindedPointCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const deblindFactorPtr = Module._vsc_buffer_bytes(deblindFactorCtxPtr);
                const deblindFactorPtrLen = Module._vsc_buffer_len(deblindFactorCtxPtr);
                const deblindFactor = Module.HEAPU8.slice(deblindFactorPtr, deblindFactorPtr + deblindFactorPtrLen);
            
                const blindedPointPtr = Module._vsc_buffer_bytes(blindedPointCtxPtr);
                const blindedPointPtrLen = Module._vsc_buffer_len(blindedPointCtxPtr);
                const blindedPoint = Module.HEAPU8.slice(blindedPointPtr, blindedPointPtr + blindedPointPtrLen);
                return { deblindFactor, blindedPoint };
            } finally {
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._vsc_buffer_delete(deblindFactorCtxPtr);
                Module._vsc_buffer_delete(blindedPointCtxPtr);
            }
        }

        deblind(password, hardenedPoint, deblindFactor, keyName) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('password', password);
            precondition.ensureByteArray('hardenedPoint', hardenedPoint);
            precondition.ensureByteArray('deblindFactor', deblindFactor);
            precondition.ensureByteArray('keyName', keyName);
            
            // Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);
            
            // Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);
            
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
            const deblindFactorSize = deblindFactor.length * deblindFactor.BYTES_PER_ELEMENT;
            const deblindFactorPtr = Module._malloc(deblindFactorSize);
            Module.HEAP8.set(deblindFactor, deblindFactorPtr);
            
            // Create C structure vsc_data_t.
            const deblindFactorCtxSize = Module._vsc_data_ctx_size();
            const deblindFactorCtxPtr = Module._malloc(deblindFactorCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(deblindFactorCtxPtr, deblindFactorPtr, deblindFactorSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const keyNameSize = keyName.length * keyName.BYTES_PER_ELEMENT;
            const keyNamePtr = Module._malloc(keyNameSize);
            Module.HEAP8.set(keyName, keyNamePtr);
            
            // Create C structure vsc_data_t.
            const keyNameCtxSize = Module._vsc_data_ctx_size();
            const keyNameCtxPtr = Module._malloc(keyNameCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyNameCtxPtr, keyNamePtr, keyNameSize);
            
            const seedCapacity = this.POINT_LEN;
            const seedCtxPtr = Module._vsc_buffer_new_with_capacity(seedCapacity);
            
            try {
                const proxyResult = Module._vscf_brainkey_client_deblind(this.ctxPtr, passwordCtxPtr, hardenedPointCtxPtr, deblindFactorCtxPtr, keyNameCtxPtr, seedCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const seedPtr = Module._vsc_buffer_bytes(seedCtxPtr);
                const seedPtrLen = Module._vsc_buffer_len(seedCtxPtr);
                const seed = Module.HEAPU8.slice(seedPtr, seedPtr + seedPtrLen);
                return seed;
            } finally {
                Module._free(passwordPtr);
                Module._free(passwordCtxPtr);
                Module._free(hardenedPointPtr);
                Module._free(hardenedPointCtxPtr);
                Module._free(deblindFactorPtr);
                Module._free(deblindFactorCtxPtr);
                Module._free(keyNamePtr);
                Module._free(keyNameCtxPtr);
                Module._vsc_buffer_delete(seedCtxPtr);
            }
        }

        verify(blindedPoint, hardenedPoint, serverPublicKey, proofValueC, proofValueS) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('blindedPoint', blindedPoint);
            precondition.ensureByteArray('hardenedPoint', hardenedPoint);
            precondition.ensureByteArray('serverPublicKey', serverPublicKey);
            precondition.ensureByteArray('proofValueC', proofValueC);
            precondition.ensureByteArray('proofValueS', proofValueS);
            
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
            const serverPublicKeySize = serverPublicKey.length * serverPublicKey.BYTES_PER_ELEMENT;
            const serverPublicKeyPtr = Module._malloc(serverPublicKeySize);
            Module.HEAP8.set(serverPublicKey, serverPublicKeyPtr);
            
            // Create C structure vsc_data_t.
            const serverPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const serverPublicKeyCtxPtr = Module._malloc(serverPublicKeyCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(serverPublicKeyCtxPtr, serverPublicKeyPtr, serverPublicKeySize);
            
            // Copy bytes from JS memory to the WASM memory.
            const proofValueCSize = proofValueC.length * proofValueC.BYTES_PER_ELEMENT;
            const proofValueCPtr = Module._malloc(proofValueCSize);
            Module.HEAP8.set(proofValueC, proofValueCPtr);
            
            // Create C structure vsc_data_t.
            const proofValueCCtxSize = Module._vsc_data_ctx_size();
            const proofValueCCtxPtr = Module._malloc(proofValueCCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(proofValueCCtxPtr, proofValueCPtr, proofValueCSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const proofValueSSize = proofValueS.length * proofValueS.BYTES_PER_ELEMENT;
            const proofValueSPtr = Module._malloc(proofValueSSize);
            Module.HEAP8.set(proofValueS, proofValueSPtr);
            
            // Create C structure vsc_data_t.
            const proofValueSCtxSize = Module._vsc_data_ctx_size();
            const proofValueSCtxPtr = Module._malloc(proofValueSCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(proofValueSCtxPtr, proofValueSPtr, proofValueSSize);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_brainkey_client_verify(this.ctxPtr, blindedPointCtxPtr, hardenedPointCtxPtr, serverPublicKeyCtxPtr, proofValueCCtxPtr, proofValueSCtxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            } finally {
                Module._free(blindedPointPtr);
                Module._free(blindedPointCtxPtr);
                Module._free(hardenedPointPtr);
                Module._free(hardenedPointCtxPtr);
                Module._free(serverPublicKeyPtr);
                Module._free(serverPublicKeyCtxPtr);
                Module._free(proofValueCPtr);
                Module._free(proofValueCCtxPtr);
                Module._free(proofValueSPtr);
                Module._free(proofValueSCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

    }

    return BrainkeyClient;
};

module.exports = initBrainkeyClient;
