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

const initMessageInfoCustomParams = (Module, modules) => {
    class MessageInfoCustomParams {

        constructor(ctxPtr) {
            this.name = 'MessageInfoCustomParams';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_custom_params_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoCustomParams(Module._vscf_message_info_custom_params_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoCustomParams(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_custom_params_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        addInt(key, value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);
            precondition.ensureNumber('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            try {
                Module._vscf_message_info_custom_params_add_int(this.ctxPtr, keyCtxPtr, value);
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
            }
        }

        addString(key, value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        addData(key, value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        clear() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_message_info_custom_params_clear(this.ctxPtr);
        }

        findInt(key, error) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_message_info_custom_params_find_int(this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
                return proxyResult;
            } finally {
                Module._free(keyPtr);
                Module._free(keyCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        findString(key, error) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            // Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_message_info_custom_params_find_string(dataResultCtxPtr, this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

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

        findData(key, error) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('key', key);

            // Copy bytes from JS memory to the WASM memory.
            const keySize = key.length * key.BYTES_PER_ELEMENT;
            const keyPtr = Module._malloc(keySize);
            Module.HEAP8.set(key, keyPtr);

            // Create C structure vsc_data_t.
            const keyCtxSize = Module._vsc_data_ctx_size();
            const keyCtxPtr = Module._malloc(keyCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyCtxPtr, keyPtr, keySize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            // Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_message_info_custom_params_find_data(dataResultCtxPtr, this.ctxPtr, keyCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

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

        hasParams() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_custom_params_has_params(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

    }

    return MessageInfoCustomParams;
};

module.exports = initMessageInfoCustomParams;
