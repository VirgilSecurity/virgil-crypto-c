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

const initKeyMaterialRng = (Module, modules) => {
    /**
     * Random number generator that generate deterministic sequence based
     * on a given seed.
     * This RNG can be used to transform key material rial to the private key.
     */
    class KeyMaterialRng {

        /**
         * Minimum length in bytes for the key material.
         */
        static get KEY_MATERIAL_LEN_MIN() {
            return 32;
        }

        get KEY_MATERIAL_LEN_MIN() {
            return KeyMaterialRng.KEY_MATERIAL_LEN_MIN;
        }

        /**
         * Maximum length in bytes for the key material.
         */
        static get KEY_MATERIAL_LEN_MAX() {
            return 512;
        }

        get KEY_MATERIAL_LEN_MAX() {
            return KeyMaterialRng.KEY_MATERIAL_LEN_MAX;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'KeyMaterialRng';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_key_material_rng_new();
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
            return new KeyMaterialRng(Module._vscf_key_material_rng_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyMaterialRng(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_key_material_rng_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Generate random bytes.
         */
        random(dataLen) {
            // assert(typeof dataLen === 'number')

            const dataCapacity = dataLen;
            const dataCtxPtr = Module._vsc_buffer_new_with_capacity(dataCapacity);

            try {
                const proxyResult = Module._vscf_key_material_rng_random(this.ctxPtr, dataLen, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const dataPtr = Module._vsc_buffer_bytes(dataCtxPtr);
                const dataPtrLen = Module._vsc_buffer_len(dataCtxPtr);
                const data = Module.HEAPU8.slice(dataPtr, dataPtr + dataPtrLen);
                return data;
            } finally {
                Module._vsc_buffer_delete(dataCtxPtr);
            }
        }

        /**
         * Retreive new seed data from the entropy sources.
         */
        reseed() {
            const proxyResult = Module._vscf_key_material_rng_reseed(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Set a new key material.
         */
        resetKeyMaterial(keyMaterial) {
            // assert(typeof keyMaterial === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keyMaterialSize = keyMaterial.length * keyMaterial.BYTES_PER_ELEMENT;
            const keyMaterialPtr = Module._malloc(keyMaterialSize);
            Module.HEAP8.set(keyMaterial, keyMaterialPtr);

            //  Create C structure vsc_data_t.
            const keyMaterialCtxSize = Module._vsc_data_ctx_size();
            const keyMaterialCtxPtr = Module._malloc(keyMaterialCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyMaterialCtxPtr, keyMaterialPtr, keyMaterialSize);

            try {
                Module._vscf_key_material_rng_reset_key_material(this.ctxPtr, keyMaterialCtxPtr);
            } finally {
                Module._free(keyMaterialPtr);
                Module._free(keyMaterialCtxPtr);
            }
        }
    }

    return KeyMaterialRng;
};

module.exports = initKeyMaterialRng;
