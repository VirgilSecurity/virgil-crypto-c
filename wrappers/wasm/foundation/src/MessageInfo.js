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


const precondition = require('./precondition');

const initMessageInfo = (Module, modules) => {
    /**
     * Handle information about an encrypted message and algorithms
     * that was used for encryption.
     */
    class MessageInfo {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'MessageInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_new();
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
            return new MessageInfo(Module._vscf_message_info_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfo(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Return information about algorithm that was used for the data encryption.
         */
        dataEncryptionAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_data_encryption_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return list with a "key recipient info" elements.
         */
        keyRecipientInfoList() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_key_recipient_info_list(this.ctxPtr);

            const jsResult = modules.KeyRecipientInfoList.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return list with a "password recipient info" elements.
         */
        passwordRecipientInfoList() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_password_recipient_info_list(this.ctxPtr);

            const jsResult = modules.PasswordRecipientInfoList.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return true if message info contains at least one custom param.
         */
        hasCustomParams() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_has_custom_params(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Provide access to the custom params object.
         * The returned object can be used to add custom params or read it.
         * If custom params object was not set then new empty object is created.
         */
        customParams() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_custom_params(this.ctxPtr);

            const jsResult = modules.MessageInfoCustomParams.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return true if cipher kdf alg info exists.
         */
        hasCipherKdfAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_has_cipher_kdf_alg_info(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return cipher kdf alg info.
         */
        cipherKdfAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_cipher_kdf_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return true if cipher padding alg info exists.
         */
        hasCipherPaddingAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_has_cipher_padding_alg_info(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return cipher padding alg info.
         */
        cipherPaddingAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_cipher_padding_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return true if footer info exists.
         */
        hasFooterInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_has_footer_info(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return footer info.
         */
        footerInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_message_info_footer_info(this.ctxPtr);

            const jsResult = modules.FooterInfo.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Remove all infos.
         */
        clear() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_message_info_clear(this.ctxPtr);
        }
    }

    return MessageInfo;
};

module.exports = initMessageInfo;
