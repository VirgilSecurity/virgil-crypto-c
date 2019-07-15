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
        initiate(senderIdentityPrivateKey, receiverIdentityPublicKey, receiverLongTermPublicKey, receiverOneTimePublicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('senderIdentityPrivateKey', senderIdentityPrivateKey);
            precondition.ensureByteArray('receiverIdentityPublicKey', receiverIdentityPublicKey);
            precondition.ensureByteArray('receiverLongTermPublicKey', receiverLongTermPublicKey);
            precondition.ensureByteArray('receiverOneTimePublicKey', receiverOneTimePublicKey);

            //  Copy bytes from JS memory to the WASM memory.
            const senderIdentityPrivateKeySize = senderIdentityPrivateKey.length * senderIdentityPrivateKey.BYTES_PER_ELEMENT;
            const senderIdentityPrivateKeyPtr = Module._malloc(senderIdentityPrivateKeySize);
            Module.HEAP8.set(senderIdentityPrivateKey, senderIdentityPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const senderIdentityPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const senderIdentityPrivateKeyCtxPtr = Module._malloc(senderIdentityPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(senderIdentityPrivateKeyCtxPtr, senderIdentityPrivateKeyPtr, senderIdentityPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverIdentityPublicKeySize = receiverIdentityPublicKey.length * receiverIdentityPublicKey.BYTES_PER_ELEMENT;
            const receiverIdentityPublicKeyPtr = Module._malloc(receiverIdentityPublicKeySize);
            Module.HEAP8.set(receiverIdentityPublicKey, receiverIdentityPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverIdentityPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverIdentityPublicKeyCtxPtr = Module._malloc(receiverIdentityPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverIdentityPublicKeyCtxPtr, receiverIdentityPublicKeyPtr, receiverIdentityPublicKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverLongTermPublicKeySize = receiverLongTermPublicKey.length * receiverLongTermPublicKey.BYTES_PER_ELEMENT;
            const receiverLongTermPublicKeyPtr = Module._malloc(receiverLongTermPublicKeySize);
            Module.HEAP8.set(receiverLongTermPublicKey, receiverLongTermPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverLongTermPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverLongTermPublicKeyCtxPtr = Module._malloc(receiverLongTermPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverLongTermPublicKeyCtxPtr, receiverLongTermPublicKeyPtr, receiverLongTermPublicKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverOneTimePublicKeySize = receiverOneTimePublicKey.length * receiverOneTimePublicKey.BYTES_PER_ELEMENT;
            const receiverOneTimePublicKeyPtr = Module._malloc(receiverOneTimePublicKeySize);
            Module.HEAP8.set(receiverOneTimePublicKey, receiverOneTimePublicKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverOneTimePublicKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverOneTimePublicKeyCtxPtr = Module._malloc(receiverOneTimePublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverOneTimePublicKeyCtxPtr, receiverOneTimePublicKeyPtr, receiverOneTimePublicKeySize);

            try {
                const proxyResult = Module._vscr_ratchet_session_initiate(this.ctxPtr, senderIdentityPrivateKeyCtxPtr, receiverIdentityPublicKeyCtxPtr, receiverLongTermPublicKeyCtxPtr, receiverOneTimePublicKeyCtxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(senderIdentityPrivateKeyPtr);
                Module._free(senderIdentityPrivateKeyCtxPtr);
                Module._free(receiverIdentityPublicKeyPtr);
                Module._free(receiverIdentityPublicKeyCtxPtr);
                Module._free(receiverLongTermPublicKeyPtr);
                Module._free(receiverLongTermPublicKeyCtxPtr);
                Module._free(receiverOneTimePublicKeyPtr);
                Module._free(receiverOneTimePublicKeyCtxPtr);
            }
        }

        /**
         * Responds to session initiation
         */
        respond(senderIdentityPublicKey, receiverIdentityPrivateKey, receiverLongTermPrivateKey, receiverOneTimePrivateKey, message) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('senderIdentityPublicKey', senderIdentityPublicKey);
            precondition.ensureByteArray('receiverIdentityPrivateKey', receiverIdentityPrivateKey);
            precondition.ensureByteArray('receiverLongTermPrivateKey', receiverLongTermPrivateKey);
            precondition.ensureByteArray('receiverOneTimePrivateKey', receiverOneTimePrivateKey);
            precondition.ensureClass('message', message, modules.RatchetMessage);

            //  Copy bytes from JS memory to the WASM memory.
            const senderIdentityPublicKeySize = senderIdentityPublicKey.length * senderIdentityPublicKey.BYTES_PER_ELEMENT;
            const senderIdentityPublicKeyPtr = Module._malloc(senderIdentityPublicKeySize);
            Module.HEAP8.set(senderIdentityPublicKey, senderIdentityPublicKeyPtr);

            //  Create C structure vsc_data_t.
            const senderIdentityPublicKeyCtxSize = Module._vsc_data_ctx_size();
            const senderIdentityPublicKeyCtxPtr = Module._malloc(senderIdentityPublicKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(senderIdentityPublicKeyCtxPtr, senderIdentityPublicKeyPtr, senderIdentityPublicKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverIdentityPrivateKeySize = receiverIdentityPrivateKey.length * receiverIdentityPrivateKey.BYTES_PER_ELEMENT;
            const receiverIdentityPrivateKeyPtr = Module._malloc(receiverIdentityPrivateKeySize);
            Module.HEAP8.set(receiverIdentityPrivateKey, receiverIdentityPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverIdentityPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverIdentityPrivateKeyCtxPtr = Module._malloc(receiverIdentityPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverIdentityPrivateKeyCtxPtr, receiverIdentityPrivateKeyPtr, receiverIdentityPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverLongTermPrivateKeySize = receiverLongTermPrivateKey.length * receiverLongTermPrivateKey.BYTES_PER_ELEMENT;
            const receiverLongTermPrivateKeyPtr = Module._malloc(receiverLongTermPrivateKeySize);
            Module.HEAP8.set(receiverLongTermPrivateKey, receiverLongTermPrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverLongTermPrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverLongTermPrivateKeyCtxPtr = Module._malloc(receiverLongTermPrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverLongTermPrivateKeyCtxPtr, receiverLongTermPrivateKeyPtr, receiverLongTermPrivateKeySize);

            //  Copy bytes from JS memory to the WASM memory.
            const receiverOneTimePrivateKeySize = receiverOneTimePrivateKey.length * receiverOneTimePrivateKey.BYTES_PER_ELEMENT;
            const receiverOneTimePrivateKeyPtr = Module._malloc(receiverOneTimePrivateKeySize);
            Module.HEAP8.set(receiverOneTimePrivateKey, receiverOneTimePrivateKeyPtr);

            //  Create C structure vsc_data_t.
            const receiverOneTimePrivateKeyCtxSize = Module._vsc_data_ctx_size();
            const receiverOneTimePrivateKeyCtxPtr = Module._malloc(receiverOneTimePrivateKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(receiverOneTimePrivateKeyCtxPtr, receiverOneTimePrivateKeyPtr, receiverOneTimePrivateKeySize);

            try {
                const proxyResult = Module._vscr_ratchet_session_respond(this.ctxPtr, senderIdentityPublicKeyCtxPtr, receiverIdentityPrivateKeyCtxPtr, receiverLongTermPrivateKeyCtxPtr, receiverOneTimePrivateKeyCtxPtr, message.ctxPtr);
                modules.RatchetError.handleStatusCode(proxyResult);
            } finally {
                Module._free(senderIdentityPublicKeyPtr);
                Module._free(senderIdentityPublicKeyCtxPtr);
                Module._free(receiverIdentityPrivateKeyPtr);
                Module._free(receiverIdentityPrivateKeyCtxPtr);
                Module._free(receiverLongTermPrivateKeyPtr);
                Module._free(receiverLongTermPrivateKeyCtxPtr);
                Module._free(receiverOneTimePrivateKeyPtr);
                Module._free(receiverOneTimePrivateKeyCtxPtr);
            }
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
