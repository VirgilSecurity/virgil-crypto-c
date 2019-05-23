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


const initMessageInfoCustomParams = Module => {
    class MessageInfoCustomParams {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr=undefined) {
            this.name = 'MessageInfoCustomParams';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_custom_params_new();
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
            return new MessageInfoCustomParams(Module._vscf_message_info_custom_params_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoCustomParams(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_custom_params_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Add custom parameter with integer value.
         */
        addInt(key, value) {
            // assert(typeof key === 'Uint8Array')
            // assert(typeof value === 'number')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            try {
                Module._vscf_message_info_custom_params_add_int(this.ctxPtr, keyCtxPtr, value);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
            }
        }

        /**
         * Add custom parameter with UTF8 string value.
         */
        addString(key, value) {
            // assert(typeof key === 'Uint8Array')
            // assert(typeof value === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            try {
                Module._vscf_message_info_custom_params_add_string(this.ctxPtr, keyCtxPtr, valueCtxPtr);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Add custom parameter with octet string value.
         */
        addData(key, value) {
            // assert(typeof key === 'Uint8Array')
            // assert(typeof value === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            try {
                Module._vscf_message_info_custom_params_add_data(this.ctxPtr, keyCtxPtr, valueCtxPtr);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Remove all parameters.
         */
        clear() {
            Module._vscf_message_info_custom_params_clear(this.ctxPtr);
        }

        /**
         * Return custom parameter with integer value.
         */
        findInt(key) {
            // assert(typeof key === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module.vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            var proxyResult = undefined;

            try {
                proxyResult = Module._vscf_message_info_custom_params_find_int(this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module.vscf_error_status(errorCtxPtr);
                FoundationError.handleStatusCode(errorStatus);
                return proxyResult;
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Return custom parameter with UTF8 string value.
         */
        findString(key) {
            // assert(typeof key === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module.vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_message_info_custom_params_find_string(dataResultCtxPtr, this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module.vscf_error_status(errorCtxPtr);
                FoundationError.handleStatusCode(errorStatus);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(errorCtxPtr);
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Return custom parameter with octet string value.
         */
        findData(key) {
            // assert(typeof key === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            //  Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module.vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_message_info_custom_params_find_data(dataResultCtxPtr, this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module.vscf_error_status(errorCtxPtr);
                FoundationError.handleStatusCode(errorStatus);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(errorCtxPtr);
                Module._free(dataResultCtxPtr);
            }
        }
    }
};

module.exports = initMessageInfoCustomParams;
