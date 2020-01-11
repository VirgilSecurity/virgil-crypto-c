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

const initPasswordRecipientInfo = (Module, modules) => {
    /**
     * Handle information about recipient that is defined by a password.
     */
    class PasswordRecipientInfo {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PasswordRecipientInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_password_recipient_info_new();
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
            return new PasswordRecipientInfo(Module._vscf_password_recipient_info_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PasswordRecipientInfo(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_password_recipient_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Create object and define all properties.
         */
        static newWithMembers(keyEncryptionAlgorithm, encryptedKey) {
            precondition.ensureImplementInterface('keyEncryptionAlgorithm', keyEncryptionAlgorithm, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            precondition.ensureByteArray('encryptedKey', encryptedKey);

            //  Copy bytes from JS memory to the WASM memory.
            const encryptedKeySize = encryptedKey.length * encryptedKey.BYTES_PER_ELEMENT;
            const encryptedKeyPtr = Module._malloc(encryptedKeySize);
            Module.HEAP8.set(encryptedKey, encryptedKeyPtr);

            //  Create C structure vsc_data_t.
            const encryptedKeyCtxSize = Module._vsc_data_ctx_size();
            const encryptedKeyCtxPtr = Module._malloc(encryptedKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(encryptedKeyCtxPtr, encryptedKeyPtr, encryptedKeySize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_password_recipient_info_new_with_members(keyEncryptionAlgorithm.ctxPtr, encryptedKeyCtxPtr);

                const jsResult = PasswordRecipientInfo.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(encryptedKeyPtr);
                Module._free(encryptedKeyCtxPtr);
            }
        }

        /**
         * Return algorithm information that was used for encryption
         * a data encryption key.
         */
        keyEncryptionAlgorithm() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_key_encryption_algorithm(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return an encrypted data encryption key.
         */
        encryptedKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_password_recipient_info_encrypted_key(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }
    }

    return PasswordRecipientInfo;
};

module.exports = initPasswordRecipientInfo;
