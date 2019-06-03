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

const initRatchetKeyId = (Module, modules) => {
    /**
     * Utils class for working with keys formats.
     */
    class RatchetKeyId {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RatchetKeyId';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscr_ratchet_key_id_new();
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
            return new RatchetKeyId(Module._vscr_ratchet_key_id_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetKeyId(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscr_ratchet_key_id_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key
         */
        computePublicKeyId(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('publicKey', publicKey);

            //  Copy bytes from JS memory to the WASM memory.
            const publicKeySize = publicKey.length * publicKey.BYTES_PER_ELEMENT;
            const publicKeyPtr = Module._malloc(publicKeySize);
            Module.HEAP8.set(publicKey, publicKeyPtr);

            //  Create C structure vsc_data_t.
            const publicKeyCtxSize = Module._vsc_data_ctx_size();
            const publicKeyCtxPtr = Module._malloc(publicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(publicKeyCtxPtr, publicKeyPtr, publicKeySize);

            const keyIdCapacity = modules.RatchetCommon.KEY_ID_LEN;
            const keyIdCtxPtr = Module._vsc_buffer_new_with_capacity(keyIdCapacity);

            try {
                const proxyResult = Module._vscr_ratchet_key_id_compute_public_key_id(this.ctxPtr, publicKeyCtxPtr, keyIdCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);

                const keyIdPtr = Module._vsc_buffer_bytes(keyIdCtxPtr);
                const keyIdPtrLen = Module._vsc_buffer_len(keyIdCtxPtr);
                const keyId = Module.HEAPU8.slice(keyIdPtr, keyIdPtr + keyIdPtrLen);
                return keyId;
            } finally {
                Module._free(publicKeyPtr);
                Module._free(publicKeyCtxPtr);
                Module._vsc_buffer_delete(keyIdCtxPtr);
            }
        }
    }

    return RatchetKeyId;
};

module.exports = initRatchetKeyId;
