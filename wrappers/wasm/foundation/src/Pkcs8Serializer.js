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

const initPkcs8Serializer = (Module, modules) => {
    class Pkcs8Serializer {

        constructor(ctxPtr) {
            this.name = 'Pkcs8Serializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_pkcs8_serializer_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Pkcs8Serializer(Module._vscf_pkcs8_serializer_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Pkcs8Serializer(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_pkcs8_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        asn1Writer(asn1Writer) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('asn1Writer', asn1Writer, 'Foundation.Asn1Writer', modules.FoundationInterfaceTag.ASN1_WRITER, modules.FoundationInterface);
            Module._vscf_pkcs8_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_pkcs8_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        serializedPublicKeyLen(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('publicKey', publicKey, modules.RawPublicKey);
            
            let proxyResult;
            proxyResult = Module._vscf_pkcs8_serializer_serialized_public_key_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        serializePublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('publicKey', publicKey, modules.RawPublicKey);
            
            const outCapacity = this.serializedPublicKeyLen(publicKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_pkcs8_serializer_serialize_public_key(this.ctxPtr, publicKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        serializedPrivateKeyLen(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('privateKey', privateKey, modules.RawPrivateKey);
            
            let proxyResult;
            proxyResult = Module._vscf_pkcs8_serializer_serialized_private_key_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        serializePrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('privateKey', privateKey, modules.RawPrivateKey);
            
            const outCapacity = this.serializedPrivateKeyLen(privateKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_pkcs8_serializer_serialize_private_key(this.ctxPtr, privateKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
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
            Module._vscf_pkcs8_serializer_setup_defaults(this.ctxPtr);
        }

        serializePublicKeyInplace(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('publicKey', publicKey, modules.RawPublicKey);
            const proxyResult = Module._vscf_pkcs8_serializer_serialize_public_key_inplace(this.ctxPtr, publicKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        serializePrivateKeyInplace(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('privateKey', privateKey, modules.RawPrivateKey);
            const proxyResult = Module._vscf_pkcs8_serializer_serialize_private_key_inplace(this.ctxPtr, privateKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

    }

    return Pkcs8Serializer;
};

module.exports = initPkcs8Serializer;
