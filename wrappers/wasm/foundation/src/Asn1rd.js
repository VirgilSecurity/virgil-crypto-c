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

const initAsn1rd = (Module, modules) => {
    class Asn1rd {

        constructor(ctxPtr) {
            this.name = 'Asn1rd';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_asn1rd_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1rd(Module._vscf_asn1rd_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Asn1rd(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_asn1rd_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        reset(data) {
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
            
            try {
                Module._vscf_asn1rd_reset(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        leftLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_left_len(this.ctxPtr);
            return proxyResult;
        }

        hasError() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_has_error(this.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        status() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_asn1rd_status(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        getTag() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_tag(this.ctxPtr);
            return proxyResult;
        }

        getLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_len(this.ctxPtr);
            return proxyResult;
        }

        getDataLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_get_data_len(this.ctxPtr);
            return proxyResult;
        }

        readTag(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        readContextTag(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_context_tag(this.ctxPtr, tag);
            return proxyResult;
        }

        readInt() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int(this.ctxPtr);
            return proxyResult;
        }

        readInt8() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int8(this.ctxPtr);
            return proxyResult;
        }

        readInt16() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int16(this.ctxPtr);
            return proxyResult;
        }

        readInt32() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int32(this.ctxPtr);
            return proxyResult;
        }

        readInt64() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_int64(this.ctxPtr);
            return proxyResult;
        }

        readUint() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint(this.ctxPtr);
            return proxyResult;
        }

        readUint8() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint8(this.ctxPtr);
            return proxyResult;
        }

        readUint16() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint16(this.ctxPtr);
            return proxyResult;
        }

        readUint32() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint32(this.ctxPtr);
            return proxyResult;
        }

        readUint64() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_uint64(this.ctxPtr);
            return proxyResult;
        }

        readBool() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_bool(this.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        readNull() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_null(this.ctxPtr);
        }

        readNullOptional() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_null_optional(this.ctxPtr);
        }

        readOctetStr() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_octet_str(this.ctxPtr);
        }

        readBitstringAsOctetStr() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_bitstring_as_octet_str(this.ctxPtr);
        }

        readUtf8Str() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_utf8_str(this.ctxPtr);
        }

        readOid() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_asn1rd_read_oid(this.ctxPtr);
        }

        readData(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);
            Module._vscf_asn1rd_read_data(this.ctxPtr, len);
        }

        readSequence() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_sequence(this.ctxPtr);
            return proxyResult;
        }

        readSet() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_read_set(this.ctxPtr);
            return proxyResult;
        }

        mbedtlsHasError(code) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('code', code);
            
            let proxyResult;
            proxyResult = Module._vscf_asn1rd_mbedtls_has_error(this.ctxPtr, code);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        readTagData(tag) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('tag', tag);
            Module._vscf_asn1rd_read_tag_data(this.ctxPtr, tag);
        }

    }

    return Asn1rd;
};

module.exports = initAsn1rd;
