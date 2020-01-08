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

const initPkcs5Pbkdf2 = (Module, modules) => {
    /**
     * Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
     */
    class Pkcs5Pbkdf2 {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Pkcs5Pbkdf2';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_pkcs5_pbkdf2_new();
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
            return new Pkcs5Pbkdf2(Module._vscf_pkcs5_pbkdf2_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Pkcs5Pbkdf2(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_pkcs5_pbkdf2_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set hmac(hmac) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('hmac', hmac, 'Foundation.Mac', modules.FoundationInterfaceTag.MAC, modules.FoundationInterface);
            Module._vscf_pkcs5_pbkdf2_release_hmac(this.ctxPtr)
            Module._vscf_pkcs5_pbkdf2_use_hmac(this.ctxPtr, hmac.ctxPtr)
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbkdf2_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Produce object with algorithm information and configuration parameters.
         */
        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_pkcs5_pbkdf2_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Restore algorithm configuration from the given object.
         */
        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_pkcs5_pbkdf2_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Derive key of the requested length from the given data.
         */
        derive(data, keyLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            precondition.ensureNumber('keyLen', keyLen);

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const keyCapacity = keyLen;
            const keyCtxPtr = Module._vsc_buffer_new_with_capacity(keyCapacity);

            try {
                Module._vscf_pkcs5_pbkdf2_derive(this.ctxPtr, dataCtxPtr, keyLen, keyCtxPtr);

                const keyPtr = Module._vsc_buffer_bytes(keyCtxPtr);
                const keyPtrLen = Module._vsc_buffer_len(keyCtxPtr);
                const key = Module.HEAPU8.slice(keyPtr, keyPtr + keyPtrLen);
                return key;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(keyCtxPtr);
            }
        }

        /**
         * Prepare algorithm to derive new key.
         */
        reset(salt, iterationCount) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('salt', salt);
            precondition.ensureNumber('iterationCount', iterationCount);

            //  Copy bytes from JS memory to the WASM memory.
            const saltSize = salt.length * salt.BYTES_PER_ELEMENT;
            const saltPtr = Module._malloc(saltSize);
            Module.HEAP8.set(salt, saltPtr);

            //  Create C structure vsc_data_t.
            const saltCtxSize = Module._vsc_data_ctx_size();
            const saltCtxPtr = Module._malloc(saltCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(saltCtxPtr, saltPtr, saltSize);

            try {
                Module._vscf_pkcs5_pbkdf2_reset(this.ctxPtr, saltCtxPtr, iterationCount);
            } finally {
                Module._free(saltPtr);
                Module._free(saltCtxPtr);
            }
        }

        /**
         * Setup application specific information (optional).
         * Can be empty.
         */
        setInfo(info) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('info', info);

            //  Copy bytes from JS memory to the WASM memory.
            const infoSize = info.length * info.BYTES_PER_ELEMENT;
            const infoPtr = Module._malloc(infoSize);
            Module.HEAP8.set(info, infoPtr);

            //  Create C structure vsc_data_t.
            const infoCtxSize = Module._vsc_data_ctx_size();
            const infoCtxPtr = Module._malloc(infoCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(infoCtxPtr, infoPtr, infoSize);

            try {
                Module._vscf_pkcs5_pbkdf2_set_info(this.ctxPtr, infoCtxPtr);
            } finally {
                Module._free(infoPtr);
                Module._free(infoCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_pkcs5_pbkdf2_setup_defaults(this.ctxPtr);
        }
    }

    return Pkcs5Pbkdf2;
};

module.exports = initPkcs5Pbkdf2;
