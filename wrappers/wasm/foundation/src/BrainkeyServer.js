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

const initBrainkeyServer = (Module, modules) => {
    class BrainkeyServer {

        static get POINT_LEN() {
            return 65;
        }

        get POINT_LEN() {
            return BrainkeyServer.POINT_LEN;
        }

        static get MPI_LEN() {
            return 32;
        }

        get MPI_LEN() {
            return BrainkeyServer.MPI_LEN;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'BrainkeyServer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_brainkey_server_new();
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
            return new BrainkeyServer(Module._vscf_brainkey_server_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new BrainkeyServer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_brainkey_server_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used for key generation, proofs, etc.
         */
        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_server_release_random(this.ctxPtr)
            Module._vscf_brainkey_server_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Random used for crypto operations to make them const-time
         */
        set operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_brainkey_server_release_operation_random(this.ctxPtr)
            Module._vscf_brainkey_server_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_brainkey_server_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateIdentitySecret() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const identitySecretCapacity = BrainkeyServer.MPI_LEN;
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

            //  Copy bytes from JS memory to the WASM memory.
            const identitySecretSize = identitySecret.length * identitySecret.BYTES_PER_ELEMENT;
            const identitySecretPtr = Module._malloc(identitySecretSize);
            Module.HEAP8.set(identitySecret, identitySecretPtr);

            //  Create C structure vsc_data_t.
            const identitySecretCtxSize = Module._vsc_data_ctx_size();
            const identitySecretCtxPtr = Module._malloc(identitySecretCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(identitySecretCtxPtr, identitySecretPtr, identitySecretSize);

            //  Copy bytes from JS memory to the WASM memory.
            const blindedPointSize = blindedPoint.length * blindedPoint.BYTES_PER_ELEMENT;
            const blindedPointPtr = Module._malloc(blindedPointSize);
            Module.HEAP8.set(blindedPoint, blindedPointPtr);

            //  Create C structure vsc_data_t.
            const blindedPointCtxSize = Module._vsc_data_ctx_size();
            const blindedPointCtxPtr = Module._malloc(blindedPointCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(blindedPointCtxPtr, blindedPointPtr, blindedPointSize);

            const hardenedPointCapacity = BrainkeyServer.POINT_LEN;
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
    }

    return BrainkeyServer;
};

module.exports = initBrainkeyServer;
