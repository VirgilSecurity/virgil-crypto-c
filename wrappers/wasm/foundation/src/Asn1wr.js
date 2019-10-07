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

const initAsn1wr = (Module, modules) => {
    /**
     * This is MbedTLS implementation of ASN.1 writer.
     */
    class Asn1wr {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Asn1wr';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_asn1wr_new();
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
            return new Asn1wr(Module._vscf_asn1wr_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1wr(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_asn1wr_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Reset all internal states and prepare to new ASN.1 writing operations.
         */
        reset(out, outLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('out', out);
            precondition.ensureNumber('outLen', outLen);
            Module._vscf_asn1wr_reset(this.ctxPtr, out, outLen);
        }

        /**
         * Finalize writing and forbid further operations.
         *
         * Note, that ASN.1 structure is always written to the buffer end, and
         * if argument "do not adjust" is false, then data is moved to the
         * beginning, otherwise - data is left at the buffer end.
         *
         * Returns length of the written bytes.
         */
        finish(doNotAdjust) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureBoolean('doNotAdjust', doNotAdjust);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_finish(this.ctxPtr, doNotAdjust);
            return proxyResult;
        }

        /**
         * Returns pointer to the inner buffer.
         */
        bytes() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_bytes(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Returns total inner buffer length.
         */
        len() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Returns how many bytes were already written to the ASN.1 structure.
         */
        writtenLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_written_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Returns how many bytes are available for writing.
         */
        unwrittenLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_unwritten_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return true if status is not "success".
         */
        hasError() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_has_error(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return error code.
         */
        status() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_asn1wr_status(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Move writing position backward for the given length.
         * Return current writing position.
         */
        reserve(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_reserve(this.ctxPtr, len);
            return proxyResult;
        }

        /**
         * Write ASN.1 tag.
         * Return count of written bytes.
         */
        writeTag(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        /**
         * Write context-specific ASN.1 tag.
         * Return count of written bytes.
         */
        writeContextTag(tag, len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_context_tag(this.ctxPtr, tag, len);
            return proxyResult;
        }

        /**
         * Write length of the following data.
         * Return count of written bytes.
         */
        writeLen(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_len(this.ctxPtr, len);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeInt(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeInt8(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int8(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeInt16(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int16(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeInt32(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int32(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeInt64(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int64(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeUint(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeUint8(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint8(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeUint16(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint16(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeUint32(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint32(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: INTEGER.
         * Return count of written bytes.
         */
        writeUint64(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint64(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: BOOLEAN.
         * Return count of written bytes.
         */
        writeBool(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureBoolean('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_bool(this.ctxPtr, value);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: NULL.
         */
        writeNull() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_null(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Write ASN.1 type: OCTET STRING.
         * Return count of written bytes.
         */
        writeOctetStr(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_asn1wr_write_octet_str(this.ctxPtr, valueCtxPtr);
                return proxyResult;
            } finally {
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Write ASN.1 type: BIT STRING with all zero unused bits.
         *
         * Return count of written bytes.
         */
        writeOctetStrAsBitstring(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_asn1wr_write_octet_str_as_bitstring(this.ctxPtr, valueCtxPtr);
                return proxyResult;
            } finally {
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Write raw data directly to the ASN.1 structure.
         * Return count of written bytes.
         * Note, use this method carefully.
         */
        writeData(data) {
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

            let proxyResult;

            try {
                proxyResult = Module._vscf_asn1wr_write_data(this.ctxPtr, dataCtxPtr);
                return proxyResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Write ASN.1 type: UTF8String.
         * Return count of written bytes.
         */
        writeUtf8Str(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_asn1wr_write_utf8_str(this.ctxPtr, valueCtxPtr);
                return proxyResult;
            } finally {
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Write ASN.1 type: OID.
         * Return count of written bytes.
         */
        writeOid(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            //  Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            //  Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(valueCtxPtr, valuePtr, valueSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_asn1wr_write_oid(this.ctxPtr, valueCtxPtr);
                return proxyResult;
            } finally {
                Module._free(valuePtr);
                Module._free(valueCtxPtr);
            }
        }

        /**
         * Mark previously written data of given length as ASN.1 type: SEQUENCE.
         * Return count of written bytes.
         */
        writeSequence(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_sequence(this.ctxPtr, len);
            return proxyResult;
        }

        /**
         * Mark previously written data of given length as ASN.1 type: SET.
         * Return count of written bytes.
         */
        writeSet(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_set(this.ctxPtr, len);
            return proxyResult;
        }
    }

    return Asn1wr;
};

module.exports = initAsn1wr;
