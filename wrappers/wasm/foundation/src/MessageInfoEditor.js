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

const initMessageInfoEditor = (Module, modules) => {
    /**
     * Add and/or remove recipients and it's parameters within message info.
     *
     * Usage:
     * 1. Unpack binary message info that was obtained from RecipientCipher.
     * 2. Add and/or remove key recipients.
     * 3. Pack MessagInfo to the binary data.
     */
    class MessageInfoEditor {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'MessageInfoEditor';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_editor_new();
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
            return new MessageInfoEditor(Module._vscf_message_info_editor_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoEditor(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_editor_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_message_info_editor_release_random(this.ctxPtr)
            Module._vscf_message_info_editor_use_random(this.ctxPtr, random.ctxPtr)
        }

        /**
         * Set dependencies to it's defaults.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_message_info_editor_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Unpack serialized message info.
         *
         * Note that recipients can only be removed but not added.
         * Note, use "unlock" method to be able to add new recipients as well.
         */
        unpack(messageInfoData) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('messageInfoData', messageInfoData);

            //  Copy bytes from JS memory to the WASM memory.
            const messageInfoDataSize = messageInfoData.length * messageInfoData.BYTES_PER_ELEMENT;
            const messageInfoDataPtr = Module._malloc(messageInfoDataSize);
            Module.HEAP8.set(messageInfoData, messageInfoDataPtr);

            //  Create C structure vsc_data_t.
            const messageInfoDataCtxSize = Module._vsc_data_ctx_size();
            const messageInfoDataCtxPtr = Module._malloc(messageInfoDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(messageInfoDataCtxPtr, messageInfoDataPtr, messageInfoDataSize);

            try {
                const proxyResult = Module._vscf_message_info_editor_unpack(this.ctxPtr, messageInfoDataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(messageInfoDataPtr);
                Module._free(messageInfoDataCtxPtr);
            }
        }

        /**
         * Decrypt encryption key this allows adding new recipients.
         */
        unlock(ownerRecipientId, ownerPrivateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('ownerRecipientId', ownerRecipientId);
            precondition.ensureImplementInterface('ownerPrivateKey', ownerPrivateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const ownerRecipientIdSize = ownerRecipientId.length * ownerRecipientId.BYTES_PER_ELEMENT;
            const ownerRecipientIdPtr = Module._malloc(ownerRecipientIdSize);
            Module.HEAP8.set(ownerRecipientId, ownerRecipientIdPtr);

            //  Create C structure vsc_data_t.
            const ownerRecipientIdCtxSize = Module._vsc_data_ctx_size();
            const ownerRecipientIdCtxPtr = Module._malloc(ownerRecipientIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(ownerRecipientIdCtxPtr, ownerRecipientIdPtr, ownerRecipientIdSize);

            try {
                const proxyResult = Module._vscf_message_info_editor_unlock(this.ctxPtr, ownerRecipientIdCtxPtr, ownerPrivateKey.ctxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(ownerRecipientIdPtr);
                Module._free(ownerRecipientIdCtxPtr);
            }
        }

        /**
         * Add recipient defined with id and public key.
         */
        addKeyRecipient(recipientId, publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('recipientId', recipientId);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const recipientIdSize = recipientId.length * recipientId.BYTES_PER_ELEMENT;
            const recipientIdPtr = Module._malloc(recipientIdSize);
            Module.HEAP8.set(recipientId, recipientIdPtr);

            //  Create C structure vsc_data_t.
            const recipientIdCtxSize = Module._vsc_data_ctx_size();
            const recipientIdCtxPtr = Module._malloc(recipientIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(recipientIdCtxPtr, recipientIdPtr, recipientIdSize);

            try {
                const proxyResult = Module._vscf_message_info_editor_add_key_recipient(this.ctxPtr, recipientIdCtxPtr, publicKey.ctxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(recipientIdPtr);
                Module._free(recipientIdCtxPtr);
            }
        }

        /**
         * Remove recipient with a given id.
         * Return false if recipient with given id was not found.
         */
        removeKeyRecipient(recipientId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('recipientId', recipientId);

            //  Copy bytes from JS memory to the WASM memory.
            const recipientIdSize = recipientId.length * recipientId.BYTES_PER_ELEMENT;
            const recipientIdPtr = Module._malloc(recipientIdSize);
            Module.HEAP8.set(recipientId, recipientIdPtr);

            //  Create C structure vsc_data_t.
            const recipientIdCtxSize = Module._vsc_data_ctx_size();
            const recipientIdCtxPtr = Module._malloc(recipientIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(recipientIdCtxPtr, recipientIdPtr, recipientIdSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_message_info_editor_remove_key_recipient(this.ctxPtr, recipientIdCtxPtr);

                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(recipientIdPtr);
                Module._free(recipientIdCtxPtr);
            }
        }

        /**
         * Remove all existent recipients.
         */
        removeAll() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_message_info_editor_remove_all(this.ctxPtr);
        }

        /**
         * Return length of serialized message info.
         * Actual length can be obtained right after applying changes.
         */
        packedLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_editor_packed_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return serialized message info.
         * Precondition: this method can be called after "apply".
         */
        pack() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const messageInfoCapacity = this.packedLen();
            const messageInfoCtxPtr = Module._vsc_buffer_new_with_capacity(messageInfoCapacity);

            try {
                Module._vscf_message_info_editor_pack(this.ctxPtr, messageInfoCtxPtr);

                const messageInfoPtr = Module._vsc_buffer_bytes(messageInfoCtxPtr);
                const messageInfoPtrLen = Module._vsc_buffer_len(messageInfoCtxPtr);
                const messageInfo = Module.HEAPU8.slice(messageInfoPtr, messageInfoPtr + messageInfoPtrLen);
                return messageInfo;
            } finally {
                Module._vsc_buffer_delete(messageInfoCtxPtr);
            }
        }
    }

    return MessageInfoEditor;
};

module.exports = initMessageInfoEditor;
