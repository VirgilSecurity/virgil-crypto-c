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

const initCipherAlgInfo = (Module, modules) => {
    class CipherAlgInfo {

        constructor(ctxPtr) {
            this.name = 'CipherAlgInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_cipher_alg_info_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new CipherAlgInfo(Module._vscf_cipher_alg_info_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new CipherAlgInfo(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_cipher_alg_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        static newWithMembers(algId, nonce) {
            precondition.ensureNumber('algId', algId);
            precondition.ensureByteArray('nonce', nonce);

            // Copy bytes from JS memory to the WASM memory.
            const nonceSize = nonce.length * nonce.BYTES_PER_ELEMENT;
            const noncePtr = Module._malloc(nonceSize);
            Module.HEAP8.set(nonce, noncePtr);

            // Create C structure vsc_data_t.
            const nonceCtxSize = Module._vsc_data_ctx_size();
            const nonceCtxPtr = Module._malloc(nonceCtxSize);

            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(nonceCtxPtr, noncePtr, nonceSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_cipher_alg_info_new_with_members(algId, nonceCtxPtr);

                const jsResult = CipherAlgInfo.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(noncePtr);
                Module._free(nonceCtxPtr);
            }
        }

        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_cipher_alg_info_alg_id(this.ctxPtr);
            return proxyResult;
        }

        nonce() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            // Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_cipher_alg_info_nonce(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

    }

    return CipherAlgInfo;
};

module.exports = initCipherAlgInfo;
