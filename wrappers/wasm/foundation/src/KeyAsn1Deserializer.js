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

const initKeyAsn1Deserializer = (Module, modules) => {
    class KeyAsn1Deserializer {

        constructor(ctxPtr) {
            this.name = 'KeyAsn1Deserializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_key_asn1_deserializer_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyAsn1Deserializer(Module._vscf_key_asn1_deserializer_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyAsn1Deserializer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_key_asn1_deserializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        asn1Reader(asn1Reader) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Reader', asn1Reader, 'Foundation.Asn1Reader', modules.FoundationInterfaceTag.ASN1_READER, modules.FoundationInterface);
            Module._vscf_key_asn1_deserializer_release_asn1_reader(this.ctxPtr)
            Module._vscf_key_asn1_deserializer_use_asn1_reader(this.ctxPtr, asn1Reader.ctxPtr)
        }

        deserializePublicKey(publicKeyData) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('publicKeyData', publicKeyData);
            
            // Copy bytes from JS memory to the WASM memory.
            const publicKeyDataSize = publicKeyData.length * publicKeyData.BYTES_PER_ELEMENT;
            const publicKeyDataPtr = Module._malloc(publicKeyDataSize);
            Module.HEAP8.set(publicKeyData, publicKeyDataPtr);
            
            // Create C structure vsc_data_t.
            const publicKeyDataCtxSize = Module._vsc_data_ctx_size();
            const publicKeyDataCtxPtr = Module._malloc(publicKeyDataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(publicKeyDataCtxPtr, publicKeyDataPtr, publicKeyDataSize);
            
            try {
                const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_public_key(this.ctxPtr, publicKeyDataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const jsResult = modules.RawPublicKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(publicKeyDataPtr);
                Module._free(publicKeyDataCtxPtr);
            }
        }

        deserializePrivateKey(privateKeyData) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('privateKeyData', privateKeyData);
            
            // Copy bytes from JS memory to the WASM memory.
            const privateKeyDataSize = privateKeyData.length * privateKeyData.BYTES_PER_ELEMENT;
            const privateKeyDataPtr = Module._malloc(privateKeyDataSize);
            Module.HEAP8.set(privateKeyData, privateKeyDataPtr);
            
            // Create C structure vsc_data_t.
            const privateKeyDataCtxSize = Module._vsc_data_ctx_size();
            const privateKeyDataCtxPtr = Module._malloc(privateKeyDataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(privateKeyDataCtxPtr, privateKeyDataPtr, privateKeyDataSize);
            
            try {
                const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_private_key(this.ctxPtr, privateKeyDataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const jsResult = modules.RawPrivateKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(privateKeyDataPtr);
                Module._free(privateKeyDataCtxPtr);
            }
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_key_asn1_deserializer_setup_defaults(this.ctxPtr);
        }

        deserializePublicKeyInplace() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_public_key_inplace(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        deserializePrivateKeyInplace() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_private_key_inplace(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        deserializePkcs8PrivateKeyInplace(seqLeftLen, version) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('seqLeftLen', seqLeftLen);
            precondition.ensureNumber('version', version);
            const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_pkcs8_private_key_inplace(this.ctxPtr, seqLeftLen, version);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        deserializeSec1PrivateKeyInplace(seqLeftLen, version, algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('seqLeftLen', seqLeftLen);
            precondition.ensureNumber('version', version);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_key_asn1_deserializer_deserialize_sec1_private_key_inplace(this.ctxPtr, seqLeftLen, version, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

    }

    return KeyAsn1Deserializer;
};

module.exports = initKeyAsn1Deserializer;
