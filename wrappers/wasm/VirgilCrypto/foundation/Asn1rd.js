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


const initAsn1rd = (Module, modules) => {
    /**
     * This is MbedTLS implementation of ASN.1 reader.
     */
    class Asn1rd {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Asn1rd';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_asn1rd_new();
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
            return new Asn1rd(Module._vscf_asn1rd_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1rd(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_asn1rd_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Reset all internal states and prepare to new ASN.1 reading operations.
         */
        reset(data) {
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

            try {
                Module._vscf_asn1rd_reset(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Return length in bytes how many bytes are left for reading.
         */
        leftLen() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_left_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return true if status is not "success".
         */
        hasError() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_has_error(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return error code.
         */
        status() {
            const proxyResult = Module._vscf_asn1rd_status(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Get tag of the current ASN.1 element.
         */
        getTag() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_tag(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Get length of the current ASN.1 element.
         */
        getLen() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Get length of the current ASN.1 element with tag and length itself.
         */
        getDataLen() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_data_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: TAG.
         * Return element length.
         */
        readTag(tag) {
            // assert(typeof tag === 'number')

            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: context-specific TAG.
         * Return element length.
         * Return 0 if current position do not points to the requested tag.
         */
        readContextTag(tag) {
            // assert(typeof tag === 'number')

            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_context_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readInt() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readInt8() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int8(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readInt16() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int16(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readInt32() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int32(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readInt64() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int64(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readUint() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readUint8() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint8(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readUint16() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint16(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readUint32() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint32(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: INTEGER.
         */
        readUint64() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint64(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: BOOLEAN.
         */
        readBool() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_bool(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Read ASN.1 type: NULL.
         */
        readNull() {
            Module._vscf_asn1rd_read_null(this.ctxPtr);
        }

        /**
         * Read ASN.1 type: NULL, only if it exists.
         * Note, this method is safe to call even no more data is left for reading.
         */
        readNullOptional() {
            Module._vscf_asn1rd_read_null_optional(this.ctxPtr);
        }

        /**
         * Read ASN.1 type: OCTET STRING.
         */
        readOctetStr() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_asn1rd_read_octet_str(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Read ASN.1 type: BIT STRING.
         */
        readBitstringAsOctetStr() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_asn1rd_read_bitstring_as_octet_str(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Read ASN.1 type: UTF8String.
         */
        readUtf8Str() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_asn1rd_read_utf8_str(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Read ASN.1 type: OID.
         */
        readOid() {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_asn1rd_read_oid(dataResultCtxPtr, this.ctxPtr);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Read raw data of given length.
         */
        readData(len) {
            // assert(typeof len === 'number')

            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_asn1rd_read_data(dataResultCtxPtr, this.ctxPtr, len);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Read ASN.1 type: CONSTRUCTED | SEQUENCE.
         * Return element length.
         */
        readSequence() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_sequence(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Read ASN.1 type: CONSTRUCTED | SET.
         * Return element length.
         */
        readSet() {
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_set(this.ctxPtr);
            return proxyResult;
        }
    }

    return Asn1rd;
};

module.exports = initAsn1rd;
