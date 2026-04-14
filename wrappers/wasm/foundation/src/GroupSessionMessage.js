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

const initGroupSessionMessage = (Module, modules) => {
    class GroupSessionMessage {

        constructor(ctxPtr) {
            this.name = 'GroupSessionMessage';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_group_session_message_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new GroupSessionMessage(Module._vscf_group_session_message_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new GroupSessionMessage(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_group_session_message_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        static get MAX_MESSAGE_LEN() {
            return 30188;
        }

        get MAX_MESSAGE_LEN() {
            return 30188;
        }

        static get MESSAGE_VERSION() {
            return 1;
        }

        get MESSAGE_VERSION() {
            return 1;
        }

        getType() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_group_session_message_get_type(this.ctxPtr);
            return proxyResult;
        }

        getSessionId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_group_session_message_get_session_id(this.ctxPtr);
        }

        getEpoch() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_group_session_message_get_epoch(this.ctxPtr);
            return proxyResult;
        }

        serializeLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_group_session_message_serialize_len(this.ctxPtr);
            return proxyResult;
        }

        serialize() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const outputCapacity = this.serializeLen();
            const outputCtxPtr = Module._vsc_buffer_new_with_capacity(outputCapacity);
            
            try {
                Module._vscf_group_session_message_serialize(this.ctxPtr, outputCtxPtr);
            
                const outputPtr = Module._vsc_buffer_bytes(outputCtxPtr);
                const outputPtrLen = Module._vsc_buffer_len(outputCtxPtr);
                const output = Module.HEAPU8.slice(outputPtr, outputPtr + outputPtrLen);
                return output;
            } finally {
                Module._vsc_buffer_delete(outputCtxPtr);
            }
        }

        static deserialize(input) {
            precondition.ensureByteArray('input', input);
            
            // Copy bytes from JS memory to the WASM memory.
            const inputSize = input.length * input.BYTES_PER_ELEMENT;
            const inputPtr = Module._malloc(inputSize);
            Module.HEAP8.set(input, inputPtr);
            
            // Create C structure vsc_data_t.
            const inputCtxSize = Module._vsc_data_ctx_size();
            const inputCtxPtr = Module._malloc(inputCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(inputCtxPtr, inputPtr, inputSize);
            
            try {
                const proxyResult = Module._vscf_group_session_message_deserialize(inputCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const jsResult = modules.Self.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(inputPtr);
                Module._free(inputCtxPtr);
            }
        }

    }

    return GroupSessionMessage;
};

module.exports = initGroupSessionMessage;
