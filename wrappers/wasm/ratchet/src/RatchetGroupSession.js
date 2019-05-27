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


const initRatchetGroupSession = (Module, modules) => {
    /**
     * Ratchet group session.
     */
    class RatchetGroupSession {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RatchetGroupSession';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscr_ratchet_group_session_new();
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
            return new RatchetGroupSession(Module._vscr_ratchet_group_session_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetGroupSession(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscr_ratchet_group_session_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random
         */
        set rng(rng) {
            Module._vscr_ratchet_group_session_release_rng(this.ctxPtr)
            Module._vscr_ratchet_group_session_use_rng(this.ctxPtr, rng.ctxPtr)
        }

        /**
         * Shows whether session was initialized.
         */
        isInitialized() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_is_initialized(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Shows whether identity private key was set.
         */
        isPrivateKeySet() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_is_private_key_set(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Shows whether my id was set.
         */
        isMyIdSet() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_is_my_id_set(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Returns current epoch.
         */
        getCurrentEpoch() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_get_current_epoch(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Setups default dependencies:
         * - RNG: CTR DRBG
         */
        setupDefaults() {
            const proxyResult = Module._vscr_ratchet_group_session_setup_defaults(this.ctxPtr);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Sets identity private key.
         */
        setPrivateKey(myPrivateKey) {
            // assert(typeof myPrivateKey === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const myPrivateKeySize = myPrivateKey.length * myPrivateKey.BYTES_PER_ELEMENT;
            const myPrivateKeyPtr = Module._malloc(myPrivateKeySize);
            Module.HEAP8.set(myPrivateKey, myPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const myPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const myPrivateKeyCtxPtr = Module._malloc(myPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(myPrivateKeyCtxPtr, myPrivateKeyPtr, myPrivateKeySize);

            try {
                const proxyResult = Module._vscr_ratchet_group_session_set_private_key(this.ctxPtr, myPrivateKeyCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(myPrivateKeyPtr);
                Module._free(myPrivateKeyCtxPtr);
            }
        }

        /**
         * Sets my id.
         */
        setMyId(myId) {
            // assert(typeof myId === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const myIdSize = myId.length * myId.BYTES_PER_ELEMENT;
            const myIdPtr = Module._malloc(myIdSize);
            Module.HEAP8.set(myId, myIdPtr);

            //  Create C structure vsc_data_t.
            const myIdCtxSize = Module._vsc_data_ctx_size();
            const myIdCtxPtr = Module._malloc(myIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(myIdCtxPtr, myIdPtr, myIdSize);

            try {
                Module._vscr_ratchet_group_session_set_my_id(this.ctxPtr, myIdCtxPtr);
            } finally {
                Module._free(myIdPtr);
                Module._free(myIdCtxPtr);
            }
        }

        /**
         * Returns my id.
         */
        getMyId() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscr_ratchet_group_session_get_my_id(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Returns session id.
         */
        getSessionId() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscr_ratchet_group_session_get_session_id(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Returns number of participants.
         */
        getParticipantsCount() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_get_participants_count(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Sets up session.
         * NOTE: Identity private key and my id should be set separately.
         */
        setupSession(message) {
            const proxyResult = Module._vscr_ratchet_group_session_setup_session(this.ctxPtr, message.ctxPtr);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Encrypts data
         */
        encrypt(plainText) {
            // assert(typeof plainText === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const plainTextSize = plainText.length * plainText.BYTES_PER_ELEMENT;
            const plainTextPtr = Module._malloc(plainTextSize);
            Module.HEAP8.set(plainText, plainTextPtr);

            //  Create C structure vsc_data_t.
            const plainTextCtxSize = Module._vsc_data_ctx_size();
            const plainTextCtxPtr = Module._malloc(plainTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plainTextCtxPtr, plainTextPtr, plainTextSize);

            const errorCtxSize = Module.vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_group_session_encrypt(this.ctxPtr, plainTextCtxPtr, errorCtxPtr);

                const errorStatus = Module.vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = modules.RatchetGroupMessage.newAndTakeCContext(proxyResult);
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
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_decrypt_len(this.ctxPtr, message.ctxPtr);
            return proxyResult;
        }

        /**
         * Decrypts message
         */
        decrypt(message) {
            const plainTextSize = RatchetGroupSession.decryptLen(message);
            const plainTextCtxPtr = Module._vsc_buffer_new_with_capacity(plainTextSize);

            try {
                const proxyResult = Module._vscr_ratchet_group_session_decrypt(this.ctxPtr, message.ctxPtr, plainTextCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);

                const plainTextPtr = Module._vsc_buffer_bytes(plainTextCtxPtr);
                const plainText = Module.HEAPU8.slice(plainTextPtr, plainTextPtr + plainTextSize);
                return plainText;
            } finally {
                Module._vsc_buffer_delete(plainTextCtxPtr);
            }
        }

        /**
         * Calculates size of buffer sufficient to store session
         */
        serializeLen() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_serialize_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Serializes session to buffer
         * NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
         */
        serialize() {
            const outputSize = RatchetGroupSession.serializeLen();
            const outputCtxPtr = Module._vsc_buffer_new_with_capacity(outputSize);

            try {
                Module._vscr_ratchet_group_session_serialize(this.ctxPtr, outputCtxPtr);

                const outputPtr = Module._vsc_buffer_bytes(outputCtxPtr);
                const output = Module.HEAPU8.slice(outputPtr, outputPtr + outputSize);
                return output;
            } finally {
                Module._vsc_buffer_delete(outputCtxPtr);
            }
        }

        /**
         * Deserializes session from buffer.
         * NOTE: Deserialized session needs dependencies to be set.
         * You should set separately:
         * - rng
         * - my private key
         */
        static deserialize(input) {
            // assert(typeof input === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const inputSize = input.length * input.BYTES_PER_ELEMENT;
            const inputPtr = Module._malloc(inputSize);
            Module.HEAP8.set(input, inputPtr);

            //  Create C structure vsc_data_t.
            const inputCtxSize = Module._vsc_data_ctx_size();
            const inputCtxPtr = Module._malloc(inputCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(inputCtxPtr, inputPtr, inputSize);

            const errorCtxSize = Module.vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_group_session_deserialize(inputCtxPtr, errorCtxPtr);

                const errorStatus = Module.vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = modules.RatchetGroupSession.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(inputPtr);
                Module._free(inputCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Creates ticket for adding participants to this session.
         * NOTE: This ticket is not suitable for removing participants from this session.
         */
        createGroupTicketForAddingParticipants() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_session_create_group_ticket_for_adding_participants(this.ctxPtr);

            const jsResult = modules.RatchetGroupTicket.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Creates ticket for adding and or removing participants to/from this session.
         */
        createGroupTicketForAddingOrRemovingParticipants() {
            const errorCtxSize = Module.vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_participants(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module.vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = modules.RatchetGroupTicket.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return RatchetGroupSession;
};

module.exports = initRatchetGroupSession;
