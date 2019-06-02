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

const initRsaPrivateKey = (Module, modules) => {
    class RsaPrivateKey {

        /**
         * Define whether a private key can be imported or not.
         */
        static get CAN_IMPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_IMPORT_PRIVATE_KEY() {
            return RsaPrivateKey.CAN_IMPORT_PRIVATE_KEY;
        }

        /**
         * Define whether a private key can be exported or not.
         */
        static get CAN_EXPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_EXPORT_PRIVATE_KEY() {
            return RsaPrivateKey.CAN_EXPORT_PRIVATE_KEY;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'RsaPrivateKey';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_rsa_private_key_new();
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
            return new RsaPrivateKey(Module._vscf_rsa_private_key_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new RsaPrivateKey(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_rsa_private_key_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            Module._vscf_rsa_private_key_release_random(this.ctxPtr)
            Module._vscf_rsa_private_key_use_random(this.ctxPtr, random.ctxPtr)
        }

        set asn1rd(asn1rd) {
            Module._vscf_rsa_private_key_release_asn1rd(this.ctxPtr)
            Module._vscf_rsa_private_key_use_asn1rd(this.ctxPtr, asn1rd.ctxPtr)
        }

        set asn1wr(asn1wr) {
            Module._vscf_rsa_private_key_release_asn1wr(this.ctxPtr)
            Module._vscf_rsa_private_key_use_asn1wr(this.ctxPtr, asn1wr.ctxPtr)
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Produce object with algorithm information and configuration parameters.
         */
        produceAlgInfo() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Restore algorithm configuration from the given object.
         */
        restoreAlgInfo(algInfo) {
            const proxyResult = Module._vscf_rsa_private_key_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Length of the key in bytes.
         */
        keyLen() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_key_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Length of the key in bits.
         */
        keyBitlen() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_key_bitlen(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Generate new private or secret key.
         * Note, this operation can be slow.
         */
        generateKey() {
            const proxyResult = Module._vscf_rsa_private_key_generate_key(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Decrypt given data.
         */
        decrypt(data) {
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

            const outCapacity = this.decryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_rsa_private_key_decrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Calculate required buffer length to hold the decrypted data.
         */
        decryptedLen(dataLen) {
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_decrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Return length in bytes required to hold signature.
         */
        signatureLen() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_signature_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Sign data given private key.
         */
        signHash(hashDigest, hashId) {
            precondition.ensureByteArray('hashDigest', hashDigest);
            precondition.ensureNumber('hashId', hashId);

            //  Copy bytes from JS memory to the WASM memory.
            const hashDigestSize = hashDigest.length * hashDigest.BYTES_PER_ELEMENT;
            const hashDigestPtr = Module._malloc(hashDigestSize);
            Module.HEAP8.set(hashDigest, hashDigestPtr);

            //  Create C structure vsc_data_t.
            const hashDigestCtxSize = Module._vsc_data_ctx_size();
            const hashDigestCtxPtr = Module._malloc(hashDigestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(hashDigestCtxPtr, hashDigestPtr, hashDigestSize);

            const signatureCapacity = this.signatureLen();
            const signatureCtxPtr = Module._vsc_buffer_new_with_capacity(signatureCapacity);

            try {
                const proxyResult = Module._vscf_rsa_private_key_sign_hash(this.ctxPtr, hashDigestCtxPtr, hashId, signatureCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const signaturePtr = Module._vsc_buffer_bytes(signatureCtxPtr);
                const signaturePtrLen = Module._vsc_buffer_len(signatureCtxPtr);
                const signature = Module.HEAPU8.slice(signaturePtr, signaturePtr + signaturePtrLen);
                return signature;
            } finally {
                Module._free(hashDigestPtr);
                Module._free(hashDigestCtxPtr);
                Module._vsc_buffer_delete(signatureCtxPtr);
            }
        }

        /**
         * Extract public part of the key.
         */
        extractPublicKey() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_extract_public_key(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Export private key in the binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA private key must be exported in format defined in
         * RFC 3447 Appendix A.1.2.
         */
        exportPrivateKey() {
            const outCapacity = this.exportedPrivateKeyLen();
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_rsa_private_key_export_private_key(this.ctxPtr, outCtxPtr);
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
         * Return length in bytes required to hold exported private key.
         */
        exportedPrivateKeyLen() {
            let proxyResult;
            proxyResult = Module._vscf_rsa_private_key_exported_private_key_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Import private key from the binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA private key must be imported from the format defined in
         * RFC 3447 Appendix A.1.2.
         */
        importPrivateKey(data) {
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

            try {
                const proxyResult = Module._vscf_rsa_private_key_import_private_key(this.ctxPtr, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            const proxyResult = Module._vscf_rsa_private_key_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Setup key length in bits that is used for key generation.
         */
        setKeygenParams(bitlen) {
            precondition.ensureNumber('bitlen', bitlen);
            Module._vscf_rsa_private_key_set_keygen_params(this.ctxPtr, bitlen);
        }
    }

    return RsaPrivateKey;
};

module.exports = initRsaPrivateKey;
