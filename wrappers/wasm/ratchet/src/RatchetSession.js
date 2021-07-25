/**
 * Copyright (C) 2015-2021 Virgil Security, Inc.
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

const initRatchetSession = (Module, modules) => {
    /**
     * Class for ratchet session between 2 participants
     */
    class RatchetSession {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RatchetSession';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscr_ratchet_session_new();
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
            return new RatchetSession(Module._vscr_ratchet_session_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetSession(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscr_ratchet_session_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Random used to generate keys
         */
        set rng(rng) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('rng', rng, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscr_ratchet_session_release_rng(this.ctxPtr)
            Module._vscr_ratchet_session_use_rng(this.ctxPtr, rng.ctxPtr)
        }

        /**
         * Setups default dependencies:
         * - RNG: CTR DRBG
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscr_ratchet_session_setup_defaults(this.ctxPtr);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Initiates session
         */
        initiate(senderIdentityPrivateKey, senderIdentityKeyId, receiverIdentityPublicKey, receiverIdentityKeyId, receiverLongTermPublicKey, receiverLongTermKeyId, receiverOneTimePublicKey, receiverOneTimeKeyId, enablePostQuantum) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('senderIdentityPrivateKey', senderIdentityPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('senderIdentityKeyId', senderIdentityKeyId);
            precondition.ensureImplementInterface('receiverIdentityPublicKey', receiverIdentityPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('receiverIdentityKeyId', receiverIdentityKeyId);
            precondition.ensureImplementInterface('receiverLongTermPublicKey', receiverLongTermPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('receiverLongTermKeyId', receiverLongTermKeyId);
            precondition.ensureImplementInterface('receiverOneTimePublicKey', receiverOneTimePublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('receiverOneTimeKeyId', receiverOneTimeKeyId);
            precondition.ensureBoolean('enablePostQuantum', enablePostQuantum);

            //  Copy bytes from JS memory to the WASM memory.
            const senderIdentityKeyIdSize = senderIdentityKeyId.length * senderIdentityKeyId.BYTES_PER_ELEMENT;
            const senderIdentityKeyIdPtr = Module._malloc(senderIdentityKeyIdSize);
            Module.HEAP8.set(senderIdentityKeyId, senderIdentityKeyIdPtr);

            //  Create C structure vsc_data_t.
            const senderIdentityKeyIdCtxSize = Module._vsc_data_ctx_size();
            const senderIdentityKeyIdCtxPtr = Module._malloc(senderIdentityKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(senderIdentityKeyIdCtxPtr, senderIdentityKeyIdPtr, senderIdentityKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverIdentityKeyIdSize = receiverIdentityKeyId.length * receiverIdentityKeyId.BYTES_PER_ELEMENT;
            const receiverIdentityKeyIdPtr = Module._malloc(receiverIdentityKeyIdSize);
            Module.HEAP8.set(receiverIdentityKeyId, receiverIdentityKeyIdPtr);

            //  Create C structure vsc_data_t.
            const receiverIdentityKeyIdCtxSize = Module._vsc_data_ctx_size();
            const receiverIdentityKeyIdCtxPtr = Module._malloc(receiverIdentityKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverIdentityKeyIdCtxPtr, receiverIdentityKeyIdPtr, receiverIdentityKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverLongTermKeyIdSize = receiverLongTermKeyId.length * receiverLongTermKeyId.BYTES_PER_ELEMENT;
            const receiverLongTermKeyIdPtr = Module._malloc(receiverLongTermKeyIdSize);
            Module.HEAP8.set(receiverLongTermKeyId, receiverLongTermKeyIdPtr);

            //  Create C structure vsc_data_t.
            const receiverLongTermKeyIdCtxSize = Module._vsc_data_ctx_size();
            const receiverLongTermKeyIdCtxPtr = Module._malloc(receiverLongTermKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverLongTermKeyIdCtxPtr, receiverLongTermKeyIdPtr, receiverLongTermKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverOneTimeKeyIdSize = receiverOneTimeKeyId.length * receiverOneTimeKeyId.BYTES_PER_ELEMENT;
            const receiverOneTimeKeyIdPtr = Module._malloc(receiverOneTimeKeyIdSize);
            Module.HEAP8.set(receiverOneTimeKeyId, receiverOneTimeKeyIdPtr);

            //  Create C structure vsc_data_t.
            const receiverOneTimeKeyIdCtxSize = Module._vsc_data_ctx_size();
            const receiverOneTimeKeyIdCtxPtr = Module._malloc(receiverOneTimeKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverOneTimeKeyIdCtxPtr, receiverOneTimeKeyIdPtr, receiverOneTimeKeyIdSize);

            try {
                const proxyResult = Module._vscr_ratchet_session_initiate(this.ctxPtr, senderIdentityPrivateKey.ctxPtr, senderIdentityKeyIdCtxPtr, receiverIdentityPublicKey.ctxPtr, receiverIdentityKeyIdCtxPtr, receiverLongTermPublicKey.ctxPtr, receiverLongTermKeyIdCtxPtr, receiverOneTimePublicKey.ctxPtr, receiverOneTimeKeyIdCtxPtr, enablePostQuantum);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(senderIdentityKeyIdPtr);
                Module._free(senderIdentityKeyIdCtxPtr);
                Module._free(receiverIdentityKeyIdPtr);
                Module._free(receiverIdentityKeyIdCtxPtr);
                Module._free(receiverLongTermKeyIdPtr);
                Module._free(receiverLongTermKeyIdCtxPtr);
                Module._free(receiverOneTimeKeyIdPtr);
                Module._free(receiverOneTimeKeyIdCtxPtr);
            }
        }

        /**
         * Initiates session
         */
        initiateNoOneTimeKey(senderIdentityPrivateKey, senderIdentityKeyId, receiverIdentityPublicKey, receiverIdentityKeyId, receiverLongTermPublicKey, receiverLongTermKeyId, enablePostQuantum) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('senderIdentityPrivateKey', senderIdentityPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('senderIdentityKeyId', senderIdentityKeyId);
            precondition.ensureImplementInterface('receiverIdentityPublicKey', receiverIdentityPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('receiverIdentityKeyId', receiverIdentityKeyId);
            precondition.ensureImplementInterface('receiverLongTermPublicKey', receiverLongTermPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('receiverLongTermKeyId', receiverLongTermKeyId);
            precondition.ensureBoolean('enablePostQuantum', enablePostQuantum);

            //  Copy bytes from JS memory to the WASM memory.
            const senderIdentityKeyIdSize = senderIdentityKeyId.length * senderIdentityKeyId.BYTES_PER_ELEMENT;
            const senderIdentityKeyIdPtr = Module._malloc(senderIdentityKeyIdSize);
            Module.HEAP8.set(senderIdentityKeyId, senderIdentityKeyIdPtr);

            //  Create C structure vsc_data_t.
            const senderIdentityKeyIdCtxSize = Module._vsc_data_ctx_size();
            const senderIdentityKeyIdCtxPtr = Module._malloc(senderIdentityKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(senderIdentityKeyIdCtxPtr, senderIdentityKeyIdPtr, senderIdentityKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverIdentityKeyIdSize = receiverIdentityKeyId.length * receiverIdentityKeyId.BYTES_PER_ELEMENT;
            const receiverIdentityKeyIdPtr = Module._malloc(receiverIdentityKeyIdSize);
            Module.HEAP8.set(receiverIdentityKeyId, receiverIdentityKeyIdPtr);

            //  Create C structure vsc_data_t.
            const receiverIdentityKeyIdCtxSize = Module._vsc_data_ctx_size();
            const receiverIdentityKeyIdCtxPtr = Module._malloc(receiverIdentityKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverIdentityKeyIdCtxPtr, receiverIdentityKeyIdPtr, receiverIdentityKeyIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverLongTermKeyIdSize = receiverLongTermKeyId.length * receiverLongTermKeyId.BYTES_PER_ELEMENT;
            const receiverLongTermKeyIdPtr = Module._malloc(receiverLongTermKeyIdSize);
            Module.HEAP8.set(receiverLongTermKeyId, receiverLongTermKeyIdPtr);

            //  Create C structure vsc_data_t.
            const receiverLongTermKeyIdCtxSize = Module._vsc_data_ctx_size();
            const receiverLongTermKeyIdCtxPtr = Module._malloc(receiverLongTermKeyIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverLongTermKeyIdCtxPtr, receiverLongTermKeyIdPtr, receiverLongTermKeyIdSize);

            try {
                const proxyResult = Module._vscr_ratchet_session_initiate_no_one_time_key(this.ctxPtr, senderIdentityPrivateKey.ctxPtr, senderIdentityKeyIdCtxPtr, receiverIdentityPublicKey.ctxPtr, receiverIdentityKeyIdCtxPtr, receiverLongTermPublicKey.ctxPtr, receiverLongTermKeyIdCtxPtr, enablePostQuantum);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(senderIdentityKeyIdPtr);
                Module._free(senderIdentityKeyIdCtxPtr);
                Module._free(receiverIdentityKeyIdPtr);
                Module._free(receiverIdentityKeyIdCtxPtr);
                Module._free(receiverLongTermKeyIdPtr);
                Module._free(receiverLongTermKeyIdCtxPtr);
            }
        }

        /**
         * Responds to session initiation
         */
        respond(senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, receiverOneTimePrivateKey, message, enablePostQuantum) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('senderIdentityPublicKey', senderIdentityPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('receiverIdentityPrivateKey', receiverIdentityPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('receiverLongTermPrivateKey', receiverLongTermPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('receiverOneTimePrivateKey', receiverOneTimePrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureClass('message', message, modules.RatchetMessage);
            precondition.ensureBoolean('enablePostQuantum', enablePostQuantum);
            const proxyResult = Module._vscr_ratchet_session_respond(this.ctxPtr, senderIdentityPublicKey.ctxPtr, receiverIdentityPrivateKey.ctxPtr, receiverLongTermPrivateKey.ctxPtr, receiverOneTimePrivateKey.ctxPtr, message.ctxPtr, enablePostQuantum);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Responds to session initiation
         */
        respondNoOneTimeKey(senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, message, enablePostQuantum) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('senderIdentityPublicKey', senderIdentityPublicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('receiverIdentityPrivateKey', receiverIdentityPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('receiverLongTermPrivateKey', receiverLongTermPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureClass('message', message, modules.RatchetMessage);
            precondition.ensureBoolean('enablePostQuantum', enablePostQuantum);
            const proxyResult = Module._vscr_ratchet_session_respond_no_one_time_key(this.ctxPtr, senderIdentityPublicKey.ctxPtr, receiverIdentityPrivateKey.ctxPtr, receiverLongTermPrivateKey.ctxPtr, message.ctxPtr, enablePostQuantum);
            modules.RatchetError.handleStatusCode(proxyResult);
        }

        /**
         * Returns flag that indicates is this session was initiated or responded
         */
        isInitiator() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_session_is_initiator(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Returns flag that indicates if session is post-quantum
         */
        isPqcEnabled() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_session_is_pqc_enabled(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Returns true if at least 1 response was successfully decrypted, false - otherwise
         */
        receivedFirstResponse() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_session_received_first_response(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Returns true if receiver had one time public key
         */
        receiverHasOneTimePublicKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_session_receiver_has_one_time_public_key(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Encrypts data
         */
        encrypt(plainText) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('plainText', plainText);

            //  Copy bytes from JS memory to the WASM memory.
            const plainTextSize = plainText.length * plainText.BYTES_PER_ELEMENT;
            const plainTextPtr = Module._malloc(plainTextSize);
            Module.HEAP8.set(plainText, plainTextPtr);

            //  Create C structure vsc_data_t.
            const plainTextCtxSize = Module._vsc_data_ctx_size();
            const plainTextCtxPtr = Module._malloc(plainTextCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(plainTextCtxPtr, plainTextPtr, plainTextSize);

            const errorCtxSize = Module._vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscr_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_session_encrypt(this.ctxPtr, plainTextCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = modules.RatchetMessage.newAndTakeCContext(proxyResult);
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
            precondition.ensureClass('message', message, modules.RatchetMessage);

            let proxyResult;
            proxyResult = Module._vscr_ratchet_session_decrypt_len(this.ctxPtr, message.ctxPtr);
            return proxyResult;
        }

        /**
         * Decrypts message
         */
        decrypt(message) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('message', message, modules.RatchetMessage);

            const plainTextCapacity = this.decryptLen(message);
            const plainTextCtxPtr = Module._vsc_buffer_new_with_capacity(plainTextCapacity);

            try {
                const proxyResult = Module._vscr_ratchet_session_decrypt(this.ctxPtr, message.ctxPtr, plainTextCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);

                const plainTextPtr = Module._vsc_buffer_bytes(plainTextCtxPtr);
                const plainTextPtrLen = Module._vsc_buffer_len(plainTextCtxPtr);
                const plainText = Module.HEAPU8.slice(plainTextPtr, plainTextPtr + plainTextPtrLen);
                return plainText;
            } finally {
                Module._vsc_buffer_delete(plainTextCtxPtr);
            }
        }

        /**
         * Serializes session to buffer
         */
        serialize() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_session_serialize(this.ctxPtr);

                const bufferResultLen = Module._vsc_buffer_len(proxyResult);
                const bufferResultPtr = Module._vsc_buffer_bytes(proxyResult);
                const bufferResult = Module.HEAPU8.slice(bufferResultPtr, bufferResultPtr + bufferResultLen);
                return bufferResult;
            } finally {
                Module._vsc_buffer_delete(proxyResult);
            }
        }

        /**
         * Deserializes session from buffer.
         * NOTE: Deserialized session needs dependencies to be set. Check setup defaults
         */
        static deserialize(input) {
            precondition.ensureByteArray('input', input);

            //  Copy bytes from JS memory to the WASM memory.
            const inputSize = input.length * input.BYTES_PER_ELEMENT;
            const inputPtr = Module._malloc(inputSize);
            Module.HEAP8.set(input, inputPtr);

            //  Create C structure vsc_data_t.
            const inputCtxSize = Module._vsc_data_ctx_size();
            const inputCtxPtr = Module._malloc(inputCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(inputCtxPtr, inputPtr, inputSize);

            const errorCtxSize = Module._vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscr_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_session_deserialize(inputCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = RatchetSession.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(inputPtr);
                Module._free(inputCtxPtr);
                Module._free(errorCtxPtr);
            }
        }
    }

    return RatchetSession;
};

module.exports = initRatchetSession;
