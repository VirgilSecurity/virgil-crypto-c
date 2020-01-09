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

const initGroupSession = (Module, modules) => {
    /**
     * Group chat encryption session.
     */
    class GroupSession {

        /**
         * Sender id len
         */
        static get SENDER_ID_LEN() {
            return 32;
        }

        get SENDER_ID_LEN() {
            return GroupSession.SENDER_ID_LEN;
        }

        /**
         * Max plain text len
         */
        static get MAX_PLAIN_TEXT_LEN() {
            return 30000;
        }

        get MAX_PLAIN_TEXT_LEN() {
            return GroupSession.MAX_PLAIN_TEXT_LEN;
        }

        /**
         * Max epochs count
         */
        static get MAX_EPOCHS_COUNT() {
            return 50;
        }

        get MAX_EPOCHS_COUNT() {
            return GroupSession.MAX_EPOCHS_COUNT;
        }

        /**
         * Salt size
         */
        static get SALT_SIZE() {
            return 32;
        }

        get SALT_SIZE() {
            return GroupSession.SALT_SIZE;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'GroupSession';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_group_session_new();
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
            return new GroupSession(Module._vscf_group_session_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new GroupSession(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_group_session_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random
         */
        set rng(rng) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('rng', rng, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_group_session_release_rng(this.ctxPtr)
            Module._vscf_group_session_use_rng(this.ctxPtr, rng.ctxPtr)
        }

        /**
         * Returns current epoch.
         */
        getCurrentEpoch() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_group_session_get_current_epoch(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Setups default dependencies:
         * - RNG: CTR DRBG
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_group_session_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Returns session id.
         */
        getSessionId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_group_session_get_session_id(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
         * Epoch message should be encrypted and signed by trusted group chat member (admin).
         */
        addEpoch(message) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('message', message, modules.GroupSessionMessage);
            const proxyResult = Module._vscf_group_session_add_epoch(this.ctxPtr, message.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Encrypts data
         */
        encrypt(plainText, privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('plainText', plainText);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const plainTextSize = plainText.length * plainText.BYTES_PER_ELEMENT;
            const plainTextPtr = Module._malloc(plainTextSize);
            Module.HEAP8.set(plainText, plainTextPtr);

            //  Create C structure vsc_data_t.
            const plainTextCtxSize = Module._vsc_data_ctx_size();
            const plainTextCtxPtr = Module._malloc(plainTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plainTextCtxPtr, plainTextPtr, plainTextSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_group_session_encrypt(this.ctxPtr, plainTextCtxPtr, privateKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.GroupSessionMessage.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(plainTextPtr);
                Module._free(plainTextCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Calculates size of buffer sufficient to store decrypted message
         */
        decryptLen(message) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('message', message, modules.GroupSessionMessage);

            let proxyResult;
            proxyResult = Module._vscf_group_session_decrypt_len(this.ctxPtr, message.ctxPtr);
            return proxyResult;
        }

        /**
         * Decrypts message
         */
        decrypt(message, publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('message', message, modules.GroupSessionMessage);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            const plainTextCapacity = this.decryptLen(message);
            const plainTextCtxPtr = Module._vsc_buffer_new_with_capacity(plainTextCapacity);

            try {
                const proxyResult = Module._vscf_group_session_decrypt(this.ctxPtr, message.ctxPtr, publicKey.ctxPtr, plainTextCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const plainTextPtr = Module._vsc_buffer_bytes(plainTextCtxPtr);
                const plainTextPtrLen = Module._vsc_buffer_len(plainTextCtxPtr);
                const plainText = Module.HEAPU8.slice(plainTextPtr, plainTextPtr + plainTextPtrLen);
                return plainText;
            } finally {
                Module._vsc_buffer_delete(plainTextCtxPtr);
            }
        }

        /**
         * Creates ticket with new key for removing participants or proactive to rotate encryption key.
         */
        createGroupTicket() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_group_session_create_group_ticket(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.GroupSessionTicket.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return GroupSession;
};

module.exports = initGroupSession;
