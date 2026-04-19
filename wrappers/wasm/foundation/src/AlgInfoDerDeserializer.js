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

const initAlgInfoDerDeserializer = (Module, modules) => {
    class AlgInfoDerDeserializer {

        constructor(ctxPtr) {
            this.name = 'AlgInfoDerDeserializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_alg_info_der_deserializer_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new AlgInfoDerDeserializer(Module._vscf_alg_info_der_deserializer_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new AlgInfoDerDeserializer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_alg_info_der_deserializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Reader(asn1Reader) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Reader', asn1Reader, 'Foundation.Asn1Reader', modules.FoundationInterfaceTag.ASN1_READER, modules.FoundationInterface);
            Module._vscf_alg_info_der_deserializer_release_asn1_reader(this.ctxPtr)
            Module._vscf_alg_info_der_deserializer_use_asn1_reader(this.ctxPtr, asn1Reader.ctxPtr)
        }

        deserialize(data) {
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
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize(this.ctxPtr, dataCtxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_alg_info_der_deserializer_setup_defaults(this.ctxPtr);
        }

        deserializeSimpleAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_simple_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeKdfAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_kdf_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeHkdfAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_hkdf_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeHmacAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_hmac_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeCipherAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_cipher_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializePbkdf2AlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_pbkdf2_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializePbes2AlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_pbes2_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeEccAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_ecc_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeCompoundKeyAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_compound_key_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeHybridKeyAlgInfo(oidId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_hybrid_key_alg_info(this.ctxPtr, oidId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        deserializeInplace() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_alg_info_der_deserializer_deserialize_inplace(this.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

    }

    return AlgInfoDerDeserializer;
};

module.exports = initAlgInfoDerDeserializer;
