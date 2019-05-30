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


const initPem = (Module, modules) => {
    /**
     * Simple PEM wrapper.
     */
    class Pem {

        /**
         * Return length in bytes required to hold wrapped PEM format.
         */
        static wrappedLen(title, dataLen) {
            // assert(typeof title === 'string')
            // assert(typeof dataLen === 'number')

            let proxyResult;
            proxyResult = Module._vscf_pem_wrapped_len(title, dataLen);
            return proxyResult;
        }

        /**
         * Takes binary data and wraps it to the simple PEM format - no
         * additional information just header-base64-footer.
         * Note, written buffer is NOT null-terminated.
         */
        static wrap(title, data) {
            // assert(typeof title === 'string')
            // assert(typeof data === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const pemCapacity = Pem.wrappedLen(title, data.length);
            const pemCtxPtr = Module._vsc_buffer_new_with_capacity(pemCapacity);

            try {
                Module._vscf_pem_wrap(title, dataCtxPtr, pemCtxPtr);

                const pemPtr = Module._vsc_buffer_bytes(pemCtxPtr);
                const pemLen = Module._vsc_buffer_len(pemCtxPtr);
                const pem = Module.HEAPU8.slice(pemPtr, pemPtr + pemLen);
                return pem;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(pemCtxPtr);
            }
        }

        /**
         * Return length in bytes required to hold unwrapped binary.
         */
        static unwrappedLen(pemLen) {
            // assert(typeof pemLen === 'number')

            let proxyResult;
            proxyResult = Module._vscf_pem_unwrapped_len(pemLen);
            return proxyResult;
        }

        /**
         * Takes PEM data and extract binary data from it.
         */
        static unwrap(pem) {
            // assert(typeof pem === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const pemSize = pem.length * pem.BYTES_PER_ELEMENT;
            const pemPtr = Module._malloc(pemSize);
            Module.HEAP8.set(pem, pemPtr);

            //  Create C structure vsc_data_t.
            const pemCtxSize = Module._vsc_data_ctx_size();
            const pemCtxPtr = Module._malloc(pemCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(pemCtxPtr, pemPtr, pemSize);

            const dataCapacity = Pem.unwrappedLen(pem.length);
            const dataCtxPtr = Module._vsc_buffer_new_with_capacity(dataCapacity);

            try {
                const proxyResult = Module._vscf_pem_unwrap(pemCtxPtr, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const dataPtr = Module._vsc_buffer_bytes(dataCtxPtr);
                const dataLen = Module._vsc_buffer_len(dataCtxPtr);
                const data = Module.HEAPU8.slice(dataPtr, dataPtr + dataLen);
                return data;
            } finally {
                Module._free(pemPtr);
                Module._free(pemCtxPtr);
                Module._vsc_buffer_delete(dataCtxPtr);
            }
        }

        /**
         * Returns PEM title if PEM data is valid, otherwise - empty data.
         */
        static title(pem) {
            // assert(typeof pem === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const pemSize = pem.length * pem.BYTES_PER_ELEMENT;
            const pemPtr = Module._malloc(pemSize);
            Module.HEAP8.set(pem, pemPtr);

            //  Create C structure vsc_data_t.
            const pemCtxSize = Module._vsc_data_ctx_size();
            const pemCtxPtr = Module._malloc(pemCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(pemCtxPtr, pemPtr, pemSize);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_pem_title(dataResultCtxPtr, pemCtxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(pemPtr);
                Module._free(pemCtxPtr);
                Module._free(dataResultCtxPtr);
            }
        }
    }

    return Pem;
};

module.exports = initPem;
