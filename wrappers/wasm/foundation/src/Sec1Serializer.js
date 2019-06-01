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

const initSec1Serializer = (Module, modules) => {
    /**
     * Implements SEC 1 key serialization to DER format.
     * See also RFC 5480 and RFC 5915.
     */
    class Sec1Serializer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Sec1Serializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_sec1_serializer_new();
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
            return new Sec1Serializer(Module._vscf_sec1_serializer_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Sec1Serializer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_sec1_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Writer(asn1Writer) {
            Module._vscf_sec1_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_sec1_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        /**
         * Calculate buffer size enough to hold serialized public key.
         *
         * Precondition: public key must be exportable.
         */
        serializedPublicKeyLen(publicKey) {
            let proxyResult;
            proxyResult = Module._vscf_sec1_serializer_serialized_public_key_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Serialize given public key to an interchangeable format.
         *
         * Precondition: public key must be exportable.
         */
        serializePublicKey(publicKey) {
            const outCapacity = this.serializedPublicKeyLen(publicKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_sec1_serializer_serialize_public_key(this.ctxPtr, publicKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Calculate buffer size enough to hold serialized private key.
         *
         * Precondition: private key must be exportable.
         */
        serializedPrivateKeyLen(privateKey) {
            let proxyResult;
            proxyResult = Module._vscf_sec1_serializer_serialized_private_key_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Serialize given private key to an interchangeable format.
         *
         * Precondition: private key must be exportable.
         */
        serializePrivateKey(privateKey) {
            const outCapacity = this.serializedPrivateKeyLen(privateKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_sec1_serializer_serialize_private_key(this.ctxPtr, privateKey.ctxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            Module._vscf_sec1_serializer_setup_defaults(this.ctxPtr);
        }

        /**
         * Serialize Public Key by using internal ASN.1 writer.
         * Note, that caller code is responsible to reset ASN.1 writer with
         * an output buffer.
         */
        serializePublicKeyInplace(publicKey) {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_sec1_serializer_serialize_public_key_inplace(this.ctxPtr, publicKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
                return proxyResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Serialize Private Key by using internal ASN.1 writer.
         * Note, that caller code is responsible to reset ASN.1 writer with
         * an output buffer.
         */
        serializePrivateKeyInplace(privateKey) {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_sec1_serializer_serialize_private_key_inplace(this.ctxPtr, privateKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
                return proxyResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return Sec1Serializer;
};

module.exports = initSec1Serializer;
