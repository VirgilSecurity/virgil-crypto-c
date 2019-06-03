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

const initSha384 = (Module, modules) => {
    /**
     * This is MbedTLS implementation of SHA384.
     */
    class Sha384 {

        /**
         * Length of the digest (hashing output) in bytes.
         */
        static get DIGEST_LEN() {
            return 48;
        }

        get DIGEST_LEN() {
            return Sha384.DIGEST_LEN;
        }

        /**
         * Block length of the digest function in bytes.
         */
        static get BLOCK_LEN() {
            return 128;
        }

        get BLOCK_LEN() {
            return Sha384.BLOCK_LEN;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Sha384';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_sha384_new();
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
            return new Sha384(Module._vscf_sha384_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Sha384(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_sha384_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_sha384_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Produce object with algorithm information and configuration parameters.
         */
        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_sha384_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Restore algorithm configuration from the given object.
         */
        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_sha384_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Calculate hash over given data.
         */
        hash(data) {
            precondition.ensureByteArray('data', data);

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const digestCapacity = this.DIGEST_LEN;
            const digestCtxPtr = Module._vsc_buffer_new_with_capacity(digestCapacity);

            try {
                Module._vscf_sha384_hash(dataCtxPtr, digestCtxPtr);

                const digestPtr = Module._vsc_buffer_bytes(digestCtxPtr);
                const digestPtrLen = Module._vsc_buffer_len(digestCtxPtr);
                const digest = Module.HEAPU8.slice(digestPtr, digestPtr + digestPtrLen);
                return digest;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(digestCtxPtr);
            }
        }

        /**
         * Start a new hashing.
         */
        start() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_sha384_start(this.ctxPtr);
        }

        /**
         * Add given data to the hash.
         */
        update(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            try {
                Module._vscf_sha384_update(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Accompilsh hashing and return it's result (a message digest).
         */
        finish() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const digestCapacity = this.DIGEST_LEN;
            const digestCtxPtr = Module._vsc_buffer_new_with_capacity(digestCapacity);

            try {
                Module._vscf_sha384_finish(this.ctxPtr, digestCtxPtr);

                const digestPtr = Module._vsc_buffer_bytes(digestCtxPtr);
                const digestPtrLen = Module._vsc_buffer_len(digestCtxPtr);
                const digest = Module.HEAPU8.slice(digestPtr, digestPtr + digestPtrLen);
                return digest;
            } finally {
                Module._vsc_buffer_delete(digestCtxPtr);
            }
        }
    }

    return Sha384;
};

module.exports = initSha384;
