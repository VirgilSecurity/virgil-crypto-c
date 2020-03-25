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

const initBrainkeyClient = (Module, modules) => {
    class BrainkeyClient {

        static get POINT_LEN() {
            return 65;
        }

        get POINT_LEN() {
            return BrainkeyClient.POINT_LEN;
        }

        static get MPI_LEN() {
            return 32;
        }

        get MPI_LEN() {
            return BrainkeyClient.MPI_LEN;
        }

        static get SEED_LEN() {
            return 32;
        }

        get SEED_LEN() {
            return BrainkeyClient.SEED_LEN;
        }

        static get MAX_PASSWORD_LEN() {
            return 128;
        }

        get MAX_PASSWORD_LEN() {
            return BrainkeyClient.MAX_PASSWORD_LEN;
        }

        static get MAX_KEY_NAME_LEN() {
            return 128;
        }

        get MAX_KEY_NAME_LEN() {
            return BrainkeyClient.MAX_KEY_NAME_LEN;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'BrainkeyClient';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_brainkey_client_new();
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
            return new BrainkeyClient(Module._vscf_brainkey_client_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyClient(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_brainkey_client_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_client_release_random(this.ctxPtr)
            Module._vscf_brainkey_client_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_client_release_operation_random(this.ctxPtr)
            Module._vscf_brainkey_client_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_brainkey_client_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        blind(password) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('password', password);

            //  Copy bytes from JS memory to the WASM memory.
            const passwordSize = password.length * password.BYTES_PER_ELEMENT;
            const passwordPtr = Module._malloc(passwordSize);
            Module.HEAP8.set(password, passwordPtr);

            //  Create C structure vsc_data_t.
            const passwordCtxSize = Module._vsc_data_ctx_size();
            const passwordCtxPtr = Module._malloc(passwordCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(passwordCtxPtr, passwordPtr, passwordSize);

            const deblindFactorCapacity = modules.BrainkeyClient.MPI_LEN;
            const deblindFactorCtxPtr = Module._vsc_buffer_new_with_capacity(deblindFactorCapacity);

            const blindedPointCapacity = modules.BrainkeyClient.POINT_LEN;
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
            const hardenedPointSize = hardenedPoint.length * hardenedPoint.BYTES_PER_ELEMENT;
            const hardenedPointPtr = Module._malloc(hardenedPointSize);
            Module.HEAP8.set(hardenedPoint, hardenedPointPtr);

            //  Create C structure vsc_data_t.
            const hardenedPointCtxSize = Module._vsc_data_ctx_size();
            const hardenedPointCtxPtr = Module._malloc(hardenedPointCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(hardenedPointCtxPtr, hardenedPointPtr, hardenedPointSize);

            //  Copy bytes from JS memory to the WASM memory.
            const deblindFactorSize = deblindFactor.length * deblindFactor.BYTES_PER_ELEMENT;
            const deblindFactorPtr = Module._malloc(deblindFactorSize);
            Module.HEAP8.set(deblindFactor, deblindFactorPtr);

            //  Create C structure vsc_data_t.
            const deblindFactorCtxSize = Module._vsc_data_ctx_size();
            const deblindFactorCtxPtr = Module._malloc(deblindFactorCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(deblindFactorCtxPtr, deblindFactorPtr, deblindFactorSize);

            //  Copy bytes from JS memory to the WASM memory.
            const keyNameSize = keyName.length * keyName.BYTES_PER_ELEMENT;
            const keyNamePtr = Module._malloc(keyNameSize);
            Module.HEAP8.set(keyName, keyNamePtr);

            //  Create C structure vsc_data_t.
            const keyNameCtxSize = Module._vsc_data_ctx_size();
            const keyNameCtxPtr = Module._malloc(keyNameCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyNameCtxPtr, keyNamePtr, keyNameSize);

            const seedCapacity = modules.BrainkeyClient.POINT_LEN;
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
    }

    return BrainkeyClient;
};

module.exports = initBrainkeyClient;
