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

const initAsn1wr = (Module, modules) => {
    class Asn1wr {

        constructor(ctxPtr) {
            this.name = 'Asn1wr';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_asn1wr_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1wr(Module._vscf_asn1wr_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1wr(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_asn1wr_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        reset(out, outLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('out', out);
            precondition.ensureNumber('outLen', outLen);
            Module._vscf_asn1wr_reset(this.ctxPtr, out, outLen);
        }

        finish(doNotAdjust) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureBoolean('doNotAdjust', doNotAdjust);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_finish(this.ctxPtr, doNotAdjust);
            return proxyResult;
        }

        bytes() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_bytes(this.ctxPtr);
            return proxyResult;
        }

        len() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_len(this.ctxPtr);
            return proxyResult;
        }

        writtenLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_written_len(this.ctxPtr);
            return proxyResult;
        }

        unwrittenLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_unwritten_len(this.ctxPtr);
            return proxyResult;
        }

        hasError() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_has_error(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        status() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_asn1wr_status(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        reserve(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_reserve(this.ctxPtr, len);
            return proxyResult;
        }

        writeTag(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        writeContextTag(tag, len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_context_tag(this.ctxPtr, tag, len);
            return proxyResult;
        }

        writeLen(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_len(this.ctxPtr, len);
            return proxyResult;
        }

        writeInt(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int(this.ctxPtr, value);
            return proxyResult;
        }

        writeInt8(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int8(this.ctxPtr, value);
            return proxyResult;
        }

        writeInt16(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int16(this.ctxPtr, value);
            return proxyResult;
        }

        writeInt32(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int32(this.ctxPtr, value);
            return proxyResult;
        }

        writeInt64(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_int64(this.ctxPtr, value);
            return proxyResult;
        }

        writeUint(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint(this.ctxPtr, value);
            return proxyResult;
        }

        writeUint8(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint8(this.ctxPtr, value);
            return proxyResult;
        }

        writeUint16(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint16(this.ctxPtr, value);
            return proxyResult;
        }

        writeUint32(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint32(this.ctxPtr, value);
            return proxyResult;
        }

        writeUint64(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_uint64(this.ctxPtr, value);
            return proxyResult;
        }

        writeBool(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureBoolean('value', value);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_bool(this.ctxPtr, value);
            return proxyResult;
        }

        writeNull() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_null(this.ctxPtr);
            return proxyResult;
        }

        writeOctetStr(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        writeOctetStrAsBitstring(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        writeData(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);

            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);

            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        writeUtf8Str(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        writeOid(value) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('value', value);

            // Copy bytes from JS memory to the WASM memory.
            const valueSize = value.length * value.BYTES_PER_ELEMENT;
            const valuePtr = Module._malloc(valueSize);
            Module.HEAP8.set(value, valuePtr);

            // Create C structure vsc_data_t.
            const valueCtxSize = Module._vsc_data_ctx_size();
            const valueCtxPtr = Module._malloc(valueCtxSize);

            // Point created vsc_data_t object to the copied bytes.
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

        writeSequence(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);

            let proxyResult;
            proxyResult = Module._vscf_asn1wr_write_sequence(this.ctxPtr, len);
            return proxyResult;
        }

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
