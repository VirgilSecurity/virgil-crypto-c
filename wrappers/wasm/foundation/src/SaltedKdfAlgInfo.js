/**
 * Copyright (C) 2015-2022 Virgil Security, Inc.
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

const initSaltedKdfAlgInfo = (Module, modules) => {
    /**
     * Handle KDF algorithms that are configured with salt and iteration count.
     */
    class SaltedKdfAlgInfo {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'SaltedKdfAlgInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_salted_kdf_alg_info_new();
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
            return new SaltedKdfAlgInfo(Module._vscf_salted_kdf_alg_info_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new SaltedKdfAlgInfo(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_salted_kdf_alg_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_salted_kdf_alg_info_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hash algorithm information.
         */
        hashAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_salted_kdf_alg_info_hash_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return KDF salt.
         */
        salt() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_salted_kdf_alg_info_salt(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Return KDF iteration count.
         * Note, can be 0 if KDF does not need the iteration count.
         */
        iterationCount() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_salted_kdf_alg_info_iteration_count(this.ctxPtr);
            return proxyResult;
        }
    }

    return SaltedKdfAlgInfo;
};

module.exports = initSaltedKdfAlgInfo;
