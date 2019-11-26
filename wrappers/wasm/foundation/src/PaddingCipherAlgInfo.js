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

const initPaddingCipherAlgInfo = (Module, modules) => {
    /**
     * Handle algorithm information about padding cipher.
     */
    class PaddingCipherAlgInfo {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PaddingCipherAlgInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_padding_cipher_alg_info_new();
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
            return new PaddingCipherAlgInfo(Module._vscf_padding_cipher_alg_info_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PaddingCipherAlgInfo(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_padding_cipher_alg_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Create algorithm an underlying cipher alg info and a padding frame.
         */
        static newWithMembers(underlyingCipher, paddingFrame) {
            precondition.ensureImplementInterface('underlyingCipher', underlyingCipher, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            precondition.ensureNumber('paddingFrame', paddingFrame);

            let proxyResult;
            proxyResult = Module._vscf_padding_cipher_alg_info_new_with_members(underlyingCipher.ctxPtr, paddingFrame);

            const jsResult = PaddingCipherAlgInfo.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_cipher_alg_info_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return underlying cipher alg info.
         */
        underlyingCipher() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_cipher_alg_info_underlying_cipher(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndUseCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return padding frame.
         */
        paddingFrame() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_cipher_alg_info_padding_frame(this.ctxPtr);
            return proxyResult;
        }
    }

    return PaddingCipherAlgInfo;
};

module.exports = initPaddingCipherAlgInfo;
