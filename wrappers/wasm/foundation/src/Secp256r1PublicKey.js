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

const initSecp256r1PublicKey = (Module, modules) => {
    class Secp256r1PublicKey {

        /**
         * Defines whether a public key can be imported or not.
         */
        static get CAN_IMPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_IMPORT_PUBLIC_KEY() {
            return Secp256r1PublicKey.CAN_IMPORT_PUBLIC_KEY;
        }

        /**
         * Define whether a public key can be exported or not.
         */
        static get CAN_EXPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_EXPORT_PUBLIC_KEY() {
            return Secp256r1PublicKey.CAN_EXPORT_PUBLIC_KEY;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Secp256r1PublicKey';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_secp256r1_public_key_new();
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
            return new Secp256r1PublicKey(Module._vscf_secp256r1_public_key_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Secp256r1PublicKey(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_secp256r1_public_key_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_secp256r1_public_key_release_random(this.ctxPtr)
            Module._vscf_secp256r1_public_key_use_random(this.ctxPtr, random.ctxPtr)
        }

        set ecies(ecies) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('ecies', ecies, modules.Ecies);
            Module._vscf_secp256r1_public_key_release_ecies(this.ctxPtr)
            Module._vscf_secp256r1_public_key_use_ecies(this.ctxPtr, ecies.ctxPtr)
        }

        /**
         * Provide algorithm identificator.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Produce object with algorithm information and configuration parameters.
         */
        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_produce_alg_info(this.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Restore algorithm configuration from the given object.
         */
        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_secp256r1_public_key_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Length of the key in bytes.
         */
        keyLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_key_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Length of the key in bits.
         */
        keyBitlen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_key_bitlen(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Encrypt given data.
         */
        encrypt(data) {
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

            const outCapacity = this.encryptedLen(data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_secp256r1_public_key_encrypt(this.ctxPtr, dataCtxPtr, outCtxPtr);
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
         * Calculate required buffer length to hold the encrypted data.
         */
        encryptedLen(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_encrypted_len(this.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Verify data with given public key and signature.
         */
        verifyHash(hashDigest, hashId, signature) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('hashDigest', hashDigest);
            precondition.ensureNumber('hashId', hashId);
            precondition.ensureByteArray('signature', signature);

            //  Copy bytes from JS memory to the WASM memory.
            const hashDigestSize = hashDigest.length * hashDigest.BYTES_PER_ELEMENT;
            const hashDigestPtr = Module._malloc(hashDigestSize);
            Module.HEAP8.set(hashDigest, hashDigestPtr);

            //  Create C structure vsc_data_t.
            const hashDigestCtxSize = Module._vsc_data_ctx_size();
            const hashDigestCtxPtr = Module._malloc(hashDigestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(hashDigestCtxPtr, hashDigestPtr, hashDigestSize);

            //  Copy bytes from JS memory to the WASM memory.
            const signatureSize = signature.length * signature.BYTES_PER_ELEMENT;
            const signaturePtr = Module._malloc(signatureSize);
            Module.HEAP8.set(signature, signaturePtr);

            //  Create C structure vsc_data_t.
            const signatureCtxSize = Module._vsc_data_ctx_size();
            const signatureCtxPtr = Module._malloc(signatureCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(signatureCtxPtr, signaturePtr, signatureSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_secp256r1_public_key_verify_hash(this.ctxPtr, hashDigestCtxPtr, hashId, signatureCtxPtr);

                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(hashDigestPtr);
                Module._free(hashDigestCtxPtr);
                Module._free(signaturePtr);
                Module._free(signatureCtxPtr);
            }
        }

        /**
         * Export public key in the binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA public key must be exported in format defined in
         * RFC 3447 Appendix A.1.1.
         */
        exportPublicKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const outCapacity = this.exportedPublicKeyLen();
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_secp256r1_public_key_export_public_key(this.ctxPtr, outCtxPtr);
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
         * Return length in bytes required to hold exported public key.
         */
        exportedPublicKeyLen() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_secp256r1_public_key_exported_public_key_len(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Import public key from the binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA public key must be imported from the format defined in
         * RFC 3447 Appendix A.1.1.
         */
        importPublicKey(data) {
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

            try {
                const proxyResult = Module._vscf_secp256r1_public_key_import_public_key(this.ctxPtr, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        /**
         * Generate ephemeral private key of the same type.
         */
        generateEphemeralKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_secp256r1_public_key_generate_ephemeral_key(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_secp256r1_public_key_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }
    }

    return Secp256r1PublicKey;
};

module.exports = initSecp256r1PublicKey;
