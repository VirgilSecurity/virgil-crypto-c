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

const initSeedEntropySource = (Module, modules) => {
    /**
     * Deterministic entropy source that is based only on the given seed.
     */
    class SeedEntropySource {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'SeedEntropySource';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_seed_entropy_source_new();
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
            return new SeedEntropySource(Module._vscf_seed_entropy_source_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new SeedEntropySource(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_seed_entropy_source_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Defines that implemented source is strong.
         */
        isStrong() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_seed_entropy_source_is_strong(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Gather entropy of the requested length.
         */
        gather(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            const outCapacity = len;
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_seed_entropy_source_gather(this.ctxPtr, len, outCtxPtr);
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
         * Set a new seed as an entropy source.
         */
        resetSeed(seed) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('seed', seed);

            //  Copy bytes from JS memory to the WASM memory.
            const seedSize = seed.length * seed.BYTES_PER_ELEMENT;
            const seedPtr = Module._malloc(seedSize);
            Module.HEAP8.set(seed, seedPtr);

            //  Create C structure vsc_data_t.
            const seedCtxSize = Module._vsc_data_ctx_size();
            const seedCtxPtr = Module._malloc(seedCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(seedCtxPtr, seedPtr, seedSize);

            try {
                Module._vscf_seed_entropy_source_reset_seed(this.ctxPtr, seedCtxPtr);
            } finally {
                Module._free(seedPtr);
                Module._free(seedCtxPtr);
            }
        }
    }

    return SeedEntropySource;
};

module.exports = initSeedEntropySource;
