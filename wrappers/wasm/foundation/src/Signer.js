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


const initSigner = (Module, modules) => {
    /**
     * Sign data of any size.
     */
    class Signer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Signer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_signer_new();
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
            return new Signer(Module._vscf_signer_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Signer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_signer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set hash(hash) {
            Module._vscf_signer_release_hash(this.ctxPtr)
            Module._vscf_signer_use_hash(this.ctxPtr, hash.ctxPtr)
        }

        /**
         * Start a processing a new signature.
         */
        reset() {
            Module._vscf_signer_reset(this.ctxPtr);
        }

        /**
         * Add given data to the signed data.
         */
        update(data) {
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

            try {
                Module._vscf_signer_update(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Return length of the signature.
         */
        signatureLen(privateKey) {
            let proxyResult;
            proxyResult = Module._vscf_signer_signature_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Accomplish signing and return signature.
         */
        sign(privateKey) {
            const signatureCapacity = this.signatureLen(privateKey);
            const signatureCtxPtr = Module._vsc_buffer_new_with_capacity(signatureCapacity);

            try {
                const proxyResult = Module._vscf_signer_sign(this.ctxPtr, privateKey.ctxPtr, signatureCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const signaturePtr = Module._vsc_buffer_bytes(signatureCtxPtr);
                const signatureLen = Module._vsc_buffer_len(signatureCtxPtr);
                const signature = Module.HEAPU8.slice(signaturePtr, signaturePtr + signatureLen);
                return signature;
            } finally {
                Module._vsc_buffer_delete(signatureCtxPtr);
            }
        }
    }

    return Signer;
};

module.exports = initSigner;
