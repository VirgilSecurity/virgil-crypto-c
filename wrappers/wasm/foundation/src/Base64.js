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

const initBase64 = (Module, modules) => {
    /**
     * Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
     */
    class Base64 {

        /**
         * Calculate length in bytes required to hold an encoded base64 string.
         */
        static encodedLen(dataLen) {
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_base64_encoded_len(dataLen);
            return proxyResult;
        }

        /**
         * Encode given data to the base64 format.
         * Note, written buffer is NOT null-terminated.
         */
        static encode(data) {
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

            const strCapacity = Base64.encodedLen(data.length);
            const strCtxPtr = Module._vsc_buffer_new_with_capacity(strCapacity);

            try {
                Module._vscf_base64_encode(dataCtxPtr, strCtxPtr);

                const strPtr = Module._vsc_buffer_bytes(strCtxPtr);
                const strPtrLen = Module._vsc_buffer_len(strCtxPtr);
                const str = Module.HEAPU8.slice(strPtr, strPtr + strPtrLen);
                return str;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(strCtxPtr);
            }
        }

        /**
         * Calculate length in bytes required to hold a decoded base64 string.
         */
        static decodedLen(strLen) {
            precondition.ensureNumber('strLen', strLen);

            let proxyResult;
            proxyResult = Module._vscf_base64_decoded_len(strLen);
            return proxyResult;
        }

        /**
         * Decode given data from the base64 format.
         */
        static decode(str) {
            precondition.ensureByteArray('str', str);

            //  Copy bytes from JS memory to the WASM memory.
            const strSize = str.length * str.BYTES_PER_ELEMENT;
            const strPtr = Module._malloc(strSize);
            Module.HEAP8.set(str, strPtr);

            //  Create C structure vsc_data_t.
            const strCtxSize = Module._vsc_data_ctx_size();
            const strCtxPtr = Module._malloc(strCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(strCtxPtr, strPtr, strSize);

            const dataCapacity = Base64.decodedLen(str.length);
            const dataCtxPtr = Module._vsc_buffer_new_with_capacity(dataCapacity);

            try {
                const proxyResult = Module._vscf_base64_decode(strCtxPtr, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const dataPtr = Module._vsc_buffer_bytes(dataCtxPtr);
                const dataPtrLen = Module._vsc_buffer_len(dataCtxPtr);
                const data = Module.HEAPU8.slice(dataPtr, dataPtr + dataPtrLen);
                return data;
            } finally {
                Module._free(strPtr);
                Module._free(strCtxPtr);
                Module._vsc_buffer_delete(dataCtxPtr);
            }
        }
    }

    return Base64;
};

module.exports = initBase64;
