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

const initRecipientCipher = (Module, modules) => {
    /**
     * This class provides hybrid encryption algorithm that combines symmetric
     * cipher for data encryption and asymmetric cipher and password based
     * cipher for symmetric key encryption.
     */
    class RecipientCipher {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RecipientCipher';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_recipient_cipher_new();
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
            return new RecipientCipher(Module._vscf_recipient_cipher_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RecipientCipher(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_recipient_cipher_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_recipient_cipher_release_random(this.ctxPtr)
            Module._vscf_recipient_cipher_use_random(this.ctxPtr, random.ctxPtr)
        }

        set encryptionCipher(encryptionCipher) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('encryptionCipher', encryptionCipher, 'Foundation.Cipher', modules.FoundationInterfaceTag.CIPHER, modules.FoundationInterface);
            Module._vscf_recipient_cipher_release_encryption_cipher(this.ctxPtr)
            Module._vscf_recipient_cipher_use_encryption_cipher(this.ctxPtr, encryptionCipher.ctxPtr)
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
                Module._vscf_recipient_cipher_add_key_recipient(this.ctxPtr, recipientIdCtxPtr, publicKey.ctxPtr);
            } finally {
                Module._free(recipientIdPtr);
                Module._free(recipientIdCtxPtr);
            }
        }

        /**
         * Remove all recipients.
         */
        clearRecipients() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_recipient_cipher_clear_recipients(this.ctxPtr);
        }

        /**
         * Provide access to the custom params object.
         * The returned object can be used to add custom params or read it.
         */
        customParams() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_recipient_cipher_custom_params(this.ctxPtr);

            const jsResult = modules.MessageInfoCustomParams.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return buffer length required to hold message info returned by the
         * "start encryption" method.
         * Precondition: all recipients and custom parameters should be set.
         */
        messageInfoLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_recipient_cipher_message_info_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Start encryption process.
         */
        startEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_recipient_cipher_start_encryption(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Return serialized message info to the buffer.
         *
         * Precondition: this method can be called after "start encryption".
         * Precondition: this method can be called before "finish encryption".
         *
         * Note, store message info to use it for decryption process,
         * or place it at the encrypted data beginning (embedding).
         *
         * Return message info - recipients public information,
         * algorithm information, etc.
         */
        packMessageInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const messageInfoCapacity = this.messageInfoLen();
            const messageInfoCtxPtr = Module._vsc_buffer_new_with_capacity(messageInfoCapacity);

            try {
                Module._vscf_recipient_cipher_pack_message_info(this.ctxPtr, messageInfoCtxPtr);

                const messageInfoPtr = Module._vsc_buffer_bytes(messageInfoCtxPtr);
                const messageInfoPtrLen = Module._vsc_buffer_len(messageInfoCtxPtr);
                const messageInfo = Module.HEAPU8.slice(messageInfoPtr, messageInfoPtr + messageInfoPtrLen);
                return messageInfo;
            } finally {
                Module._vsc_buffer_delete(messageInfoCtxPtr);
            }
        }

        /**
         * Return buffer length required to hold output of the method
         * "process encryption" and method "finish" during encryption.
         */
        encryptionOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_recipient_cipher_encryption_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Process encryption of a new portion of data.
         */
        processEncryption(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.encryptionOutLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_recipient_cipher_process_encryption(this.ctxPtr, dataCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Accomplish encryption.
         */
        finishEncryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const outCapacity = this.encryptionOutLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_recipient_cipher_finish_encryption(this.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Initiate decryption process with a recipient private key.
         * Message info can be empty if it was embedded to encrypted data.
         */
        startDecryptionWithKey(recipientId, privateKey, messageInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('recipientId', recipientId);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('messageInfo', messageInfo);

            //  Copy bytes from JS memory to the WASM memory.
            const recipientIdSize = recipientId.length * recipientId.BYTES_PER_ELEMENT;
            const recipientIdPtr = Module._malloc(recipientIdSize);
            Module.HEAP8.set(recipientId, recipientIdPtr);

            //  Create C structure vsc_data_t.
            const recipientIdCtxSize = Module._vsc_data_ctx_size();
            const recipientIdCtxPtr = Module._malloc(recipientIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(recipientIdCtxPtr, recipientIdPtr, recipientIdSize);

            //  Copy bytes from JS memory to the WASM memory.
            const messageInfoSize = messageInfo.length * messageInfo.BYTES_PER_ELEMENT;
            const messageInfoPtr = Module._malloc(messageInfoSize);
            Module.HEAP8.set(messageInfo, messageInfoPtr);

            //  Create C structure vsc_data_t.
            const messageInfoCtxSize = Module._vsc_data_ctx_size();
            const messageInfoCtxPtr = Module._malloc(messageInfoCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(messageInfoCtxPtr, messageInfoPtr, messageInfoSize);

            try {
                const proxyResult = Module._vscf_recipient_cipher_start_decryption_with_key(this.ctxPtr, recipientIdCtxPtr, privateKey.ctxPtr, messageInfoCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(recipientIdPtr);
                Module._free(recipientIdCtxPtr);
                Module._free(messageInfoPtr);
                Module._free(messageInfoCtxPtr);
            }
        }

        /**
         * Return buffer length required to hold output of the method
         * "process decryption" and method "finish" during decryption.
         */
        decryptionOutLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_recipient_cipher_decryption_out_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Process with a new portion of data.
         * Return error if data can not be encrypted or decrypted.
         */
        processDecryption(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const outCapacity = this.decryptionOutLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_recipient_cipher_process_decryption(this.ctxPtr, dataCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Accomplish decryption.
         */
        finishDecryption() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const outCapacity = this.decryptionOutLen(0);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_recipient_cipher_finish_decryption(this.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }
    }

    return RecipientCipher;
};

module.exports = initRecipientCipher;
