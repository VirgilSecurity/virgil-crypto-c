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


const initKeyAsn1Deserializer = (Module, modules) => {
    /**
     * Implements PKCS#8 and SEC1 key deserialization from DER / PEM format.
     */
    class KeyAsn1Deserializer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'KeyAsn1Deserializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_key_asn1_deserializer_new();
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
            return new KeyAsn1Deserializer(Module._vscf_key_asn1_deserializer_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyAsn1Deserializer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_key_asn1_deserializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Reader(asn1Reader) {
            Module._vscf_key_asn1_deserializer_release_asn1_reader(this.ctxPtr)
            Module._vscf_key_asn1_deserializer_use_asn1_reader(this.ctxPtr, asn1Reader.ctxPtr)
        }

        /**
         * Deserialize given public key as an interchangeable format to the object.
         */
        deserializePublicKey(publicKeyData) {
            // assert(typeof publicKeyData === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const publicKeyDataSize = publicKeyData.length * publicKeyData.BYTES_PER_ELEMENT;
            const publicKeyDataPtr = Module._malloc(publicKeyDataSize);
            Module.HEAP8.set(publicKeyData, publicKeyDataPtr);

            //  Create C structure vsc_data_t.
            const publicKeyDataCtxSize = Module._vsc_data_ctx_size();
            const publicKeyDataCtxPtr = Module._malloc(publicKeyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(publicKeyDataCtxPtr, publicKeyDataPtr, publicKeyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_asn1_deserializer_deserialize_public_key(this.ctxPtr, publicKeyDataCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(publicKeyDataPtr);
                Module._free(publicKeyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Deserialize given private key as an interchangeable format to the object.
         */
        deserializePrivateKey(privateKeyData) {
            // assert(typeof privateKeyData === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const privateKeyDataSize = privateKeyData.length * privateKeyData.BYTES_PER_ELEMENT;
            const privateKeyDataPtr = Module._malloc(privateKeyDataSize);
            Module.HEAP8.set(privateKeyData, privateKeyDataPtr);

            //  Create C structure vsc_data_t.
            const privateKeyDataCtxSize = Module._vsc_data_ctx_size();
            const privateKeyDataCtxPtr = Module._malloc(privateKeyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(privateKeyDataCtxPtr, privateKeyDataPtr, privateKeyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_asn1_deserializer_deserialize_private_key(this.ctxPtr, privateKeyDataCtxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(privateKeyDataPtr);
                Module._free(privateKeyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            Module._vscf_key_asn1_deserializer_setup_defaults(this.ctxPtr);
        }

        /**
         * Deserialize Public Key by using internal ASN.1 reader.
         * Note, that caller code is responsible to reset ASN.1 reader with
         * an input buffer.
         */
        deserializePublicKeyInplace() {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_asn1_deserializer_deserialize_public_key_inplace(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Deserialize Private Key by using internal ASN.1 reader.
         * Note, that caller code is responsible to reset ASN.1 reader with
         * an input buffer.
         */
        deserializePrivateKeyInplace() {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_key_asn1_deserializer_deserialize_private_key_inplace(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return KeyAsn1Deserializer;
};

module.exports = initKeyAsn1Deserializer;
