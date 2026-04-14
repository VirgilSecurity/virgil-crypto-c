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

const initPasswordRecipientInfoList = (Module, modules) => {
    class PasswordRecipientInfoList {

        constructor(ctxPtr) {
            this.name = 'PasswordRecipientInfoList';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_password_recipient_info_list_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PasswordRecipientInfoList(Module._vscf_password_recipient_info_list_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PasswordRecipientInfoList(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_password_recipient_info_list_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        hasItem() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_has_item(this.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        item() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_item(this.ctxPtr);
            
            const jsResult = modules.PasswordRecipientInfo.newAndUseCContext(proxyResult);
            return jsResult;
        }

        hasNext() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_has_next(this.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        next() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_next(this.ctxPtr);
            
            const jsResult = modules.Self.newAndUseCContext(proxyResult);
            return jsResult;
        }

        hasPrev() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_has_prev(this.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        prev() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_password_recipient_info_list_prev(this.ctxPtr);
            
            const jsResult = modules.Self.newAndUseCContext(proxyResult);
            return jsResult;
        }

        clear() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_password_recipient_info_list_clear(this.ctxPtr);
        }

    }

    return PasswordRecipientInfoList;
};

module.exports = initPasswordRecipientInfoList;
