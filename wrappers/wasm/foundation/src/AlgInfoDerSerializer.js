/**
 * Copyright (C) 2015-2026 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

const initAlgInfoDerSerializer = (Module, modules) => {
    class AlgInfoDerSerializer {

        constructor(ctxPtr) {
            this.name = 'AlgInfoDerSerializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_alg_info_der_serializer_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new AlgInfoDerSerializer(Module._vscf_alg_info_der_serializer_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new AlgInfoDerSerializer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_alg_info_der_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Writer(asn1Writer) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Writer', asn1Writer, 'Foundation.Asn1Writer', modules.FoundationInterfaceTag.ASN1_WRITER, modules.FoundationInterface);
            Module._vscf_alg_info_der_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_alg_info_der_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        serializedLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serialize(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            const outCapacity = this.serializedLen(algInfo);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                Module._vscf_alg_info_der_serializer_serialize(this.ctxPtr, algInfo.ctxPtr, outCtxPtr);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_alg_info_der_serializer_setup_defaults(this.ctxPtr);
        }

        static isAlgRequireNullParams(algId) {
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_is_alg_require_null_params(algId);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        isAlgRequireNullParams(algId) {
            return AlgInfoDerSerializer.isAlgRequireNullParams(algId);
        }

        serializedSimpleAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_simple_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeSimpleAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_simple_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedKdfAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_kdf_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeKdfAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_kdf_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedHkdfAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_hkdf_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeHkdfAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_hkdf_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedHmacAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_hmac_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeHmacAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_hmac_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedCipherAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_cipher_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeCipherAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_cipher_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedChunkedAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_chunked_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeChunkedAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_chunked_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedPbkdf2AlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_pbkdf2_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializePbkdf2AlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_pbkdf2_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedPbes2AlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_pbes2_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializePbes2AlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_pbes2_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedEccAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_ecc_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeEccAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_ecc_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedCompoundKeyAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_compound_key_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeCompoundKeyAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_compound_key_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializedHybridKeyAlgInfoLen(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_hybrid_key_alg_info_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeHybridKeyAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_hybrid_key_alg_info(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        serializeInplace(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_inplace(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

    }

    return AlgInfoDerSerializer;
};

module.exports = initAlgInfoDerSerializer;
