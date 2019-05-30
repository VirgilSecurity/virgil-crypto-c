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


const initRatchetGroupMessage = (Module, modules) => {
    /**
     * Class represents ratchet group message
     */
    class RatchetGroupMessage {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RatchetGroupMessage';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscr_ratchet_group_message_new();
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
            return new RatchetGroupMessage(Module._vscr_ratchet_group_message_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RatchetGroupMessage(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscr_ratchet_group_message_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Returns message type.
         */
        getType() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_message_get_type(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Returns session id.
         * This method should be called only for group info type.
         */
        getSessionId() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscr_ratchet_group_message_get_session_id(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Returns number of public keys.
         * This method should be called only for group info message type.
         */
        getPubKeyCount() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_message_get_pub_key_count(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Returns public key id for some participant id.
         * This method should be called only for group info message type.
         */
        getPubKeyId(participantId) {
            // assert(typeof participantId === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const participantIdSize = participantId.length * participantId.BYTES_PER_ELEMENT;
            const participantIdPtr = Module._malloc(participantIdSize);
            Module.HEAP8.set(participantId, participantIdPtr);

            //  Create C structure vsc_data_t.
            const participantIdCtxSize = Module._vsc_data_ctx_size();
            const participantIdCtxPtr = Module._malloc(participantIdCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(participantIdCtxPtr, participantIdPtr, participantIdSize);

            const errorCtxSize = Module._vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_group_message_get_pub_key_id(this.ctxPtr, participantIdCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const bufferResultLen = Module._vsc_buffer_len(proxyResult);
                const bufferResultPtr = Module._vsc_buffer_bytes(proxyResult);
                const bufferResult = Module.HEAPU8.slice(bufferResultPtr, bufferResultPtr + bufferResultLen);
                return bufferResult;
            } finally {
                Module._free(participantIdPtr);
                Module._free(participantIdCtxPtr);
                Module._free(errorCtxPtr);
                Module._vsc_buffer_delete(proxyResult);
            }
        }

        /**
         * Returns message sender id.
         * This method should be called only for regular message type.
         */
        getSenderId() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscr_ratchet_group_message_get_sender_id(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Buffer len to serialize this class.
         */
        serializeLen() {
            let proxyResult;
            proxyResult = Module._vscr_ratchet_group_message_serialize_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Serializes instance.
         */
        serialize() {
            const outputCapacity = this.serializeLen();
            const outputCtxPtr = Module._vsc_buffer_new_with_capacity(outputCapacity);

            try {
                Module._vscr_ratchet_group_message_serialize(this.ctxPtr, outputCtxPtr);

                const outputPtr = Module._vsc_buffer_bytes(outputCtxPtr);
                const outputLen = Module._vsc_buffer_len(outputCtxPtr);
                const output = Module.HEAPU8.slice(outputPtr, outputPtr + outputLen);
                return output;
            } finally {
                Module._vsc_buffer_delete(outputCtxPtr);
            }
        }

        /**
         * Deserializes instance.
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

            const errorCtxSize = Module._vscr_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscr_ratchet_group_message_deserialize(inputCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscr_error_status(errorCtxPtr);
                modules.RatchetError.handleStatusCode(errorStatus);

                const jsResult = RatchetGroupMessage.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(inputPtr);
                Module._free(inputCtxPtr);
                Module._free(errorCtxPtr);
            }
        }
    }

    return RatchetGroupMessage;
};

module.exports = initRatchetGroupMessage;
