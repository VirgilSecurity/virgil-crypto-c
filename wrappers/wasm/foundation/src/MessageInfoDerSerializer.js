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


const initMessageInfoDerSerializer = (Module, modules) => {
    /**
     * CMS based implementation of the class "message info" serialization.
     */
    class MessageInfoDerSerializer {

        static get PREFIX_LEN() {
            return 32;
        }

        get PREFIX_LEN() {
            return MessageInfoDerSerializer.PREFIX_LEN;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'MessageInfoDerSerializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_message_info_der_serializer_new();
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
            return new MessageInfoDerSerializer(Module._vscf_message_info_der_serializer_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new MessageInfoDerSerializer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_message_info_der_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Reader(asn1Reader) {
            Module._vscf_message_info_der_serializer_release_asn1_reader(this.ctxPtr)
            Module._vscf_message_info_der_serializer_use_asn1_reader(this.ctxPtr, asn1Reader.ctxPtr)
        }

        set asn1Writer(asn1Writer) {
            Module._vscf_message_info_der_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_message_info_der_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        /**
         * Return buffer size enough to hold serialized message info.
         */
        serializedLen(messageInfo) {
            let proxyResult;
            proxyResult = Module._vscf_message_info_der_serializer_serialized_len(this.ctxPtr, messageInfo.ctxPtr);
            return proxyResult;
        }

        /**
         * Serialize class "message info".
         */
        serialize(messageInfo) {
            const outCapacity = this.serializedLen(messageInfo);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                Module._vscf_message_info_der_serializer_serialize(this.ctxPtr, messageInfo.ctxPtr, outCtxPtr);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Read message info prefix from the given data, and if it is valid,
         * return a length of bytes of the whole message info.
         *
         * Zero returned if length can not be determined from the given data,
         * and this means that there is no message info at the data beginning.
         */
        readPrefix(data) {
            // assert(typeof data === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_message_info_der_serializer_read_prefix(this.ctxPtr, dataCtxPtr);
                return proxyResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Deserialize class "message info".
         */
        deserialize(data) {
            // assert(typeof data === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            //  Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_message_info_der_serializer_deserialize(this.ctxPtr, dataCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.MessageInfo.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            Module._vscf_message_info_der_serializer_setup_defaults(this.ctxPtr);
        }
    }

    return MessageInfoDerSerializer;
};

module.exports = initMessageInfoDerSerializer;
