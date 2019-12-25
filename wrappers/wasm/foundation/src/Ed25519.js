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

const initEd25519 = (Module, modules) => {
    /**
     * This is implementation of Ed25519 elliptic curve algorithms.
     */
    class Ed25519 {

        /**
         * Defines whether a public key can be imported or not.
         */
        static get CAN_IMPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_IMPORT_PUBLIC_KEY() {
            return Ed25519.CAN_IMPORT_PUBLIC_KEY;
        }

        /**
         * Define whether a public key can be exported or not.
         */
        static get CAN_EXPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_EXPORT_PUBLIC_KEY() {
            return Ed25519.CAN_EXPORT_PUBLIC_KEY;
        }

        /**
         * Define whether a private key can be imported or not.
         */
        static get CAN_IMPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_IMPORT_PRIVATE_KEY() {
            return Ed25519.CAN_IMPORT_PRIVATE_KEY;
        }

        /**
         * Define whether a private key can be exported or not.
         */
        static get CAN_EXPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_EXPORT_PRIVATE_KEY() {
            return Ed25519.CAN_EXPORT_PRIVATE_KEY;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'Ed25519';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_ed25519_new();
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
            return new Ed25519(Module._vscf_ed25519_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Ed25519(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_ed25519_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_ed25519_release_random(this.ctxPtr)
            Module._vscf_ed25519_use_random(this.ctxPtr, random.ctxPtr)
        }

        set ecies(ecies) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('ecies', ecies, modules.Ecies);
            Module._vscf_ed25519_release_ecies(this.ctxPtr)
            Module._vscf_ed25519_use_ecies(this.ctxPtr, ecies.ctxPtr)
        }

        /**
         * Generate ephemeral private key of the same type.
         * Note, this operation might be slow.
         */
        generateEphemeralKey(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_generate_ephemeral_key(this.ctxPtr, key.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Import public key from the raw binary format.
         *
         * Return public key that is adopted and optimized to be used
         * with this particular algorithm.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA public key must be imported from the format defined in
         * RFC 3447 Appendix A.1.1.
         */
        importPublicKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPublicKey);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_import_public_key(this.ctxPtr, rawKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Import public key from the raw binary format.
         */
        importPublicKeyData(keyData, keyAlgInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('keyData', keyData);
            precondition.ensureImplementInterface('keyAlgInfo', keyAlgInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const keyDataSize = keyData.length * keyData.BYTES_PER_ELEMENT;
            const keyDataPtr = Module._malloc(keyDataSize);
            Module.HEAP8.set(keyData, keyDataPtr);

            //  Create C structure vsc_data_t.
            const keyDataCtxSize = Module._vsc_data_ctx_size();
            const keyDataCtxPtr = Module._malloc(keyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyDataCtxPtr, keyDataPtr, keyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_import_public_key_data(this.ctxPtr, keyDataCtxPtr, keyAlgInfo.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(keyDataPtr);
                Module._free(keyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Export public key to the raw binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA public key must be exported in format defined in
         * RFC 3447 Appendix A.1.1.
         */
        exportPublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_export_public_key(this.ctxPtr, publicKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawPublicKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Return length in bytes required to hold exported public key.
         */
        exportedPublicKeyDataLen(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_exported_public_key_data_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Export public key to the raw binary format without algorithm information.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA public key must be exported in format defined in
         * RFC 3447 Appendix A.1.1.
         */
        exportPublicKeyData(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            const outCapacity = this.exportedPublicKeyDataLen(publicKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_export_public_key_data(this.ctxPtr, publicKey.ctxPtr, outCtxPtr);
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
         * Import private key from the raw binary format.
         *
         * Return private key that is adopted and optimized to be used
         * with this particular algorithm.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA private key must be imported from the format defined in
         * RFC 3447 Appendix A.1.2.
         */
        importPrivateKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPrivateKey);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_import_private_key(this.ctxPtr, rawKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Import private key from the raw binary format.
         */
        importPrivateKeyData(keyData, keyAlgInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('keyData', keyData);
            precondition.ensureImplementInterface('keyAlgInfo', keyAlgInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const keyDataSize = keyData.length * keyData.BYTES_PER_ELEMENT;
            const keyDataPtr = Module._malloc(keyDataSize);
            Module.HEAP8.set(keyData, keyDataPtr);

            //  Create C structure vsc_data_t.
            const keyDataCtxSize = Module._vsc_data_ctx_size();
            const keyDataCtxPtr = Module._malloc(keyDataCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(keyDataCtxPtr, keyDataPtr, keyDataSize);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_import_private_key_data(this.ctxPtr, keyDataCtxPtr, keyAlgInfo.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(keyDataPtr);
                Module._free(keyDataCtxPtr);
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Export private key in the raw binary format.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA private key must be exported in format defined in
         * RFC 3447 Appendix A.1.2.
         */
        exportPrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_export_private_key(this.ctxPtr, privateKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.RawPrivateKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Return length in bytes required to hold exported private key.
         */
        exportedPrivateKeyDataLen(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_exported_private_key_data_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Export private key to the raw binary format without algorithm information.
         *
         * Binary format must be defined in the key specification.
         * For instance, RSA private key must be exported in format defined in
         * RFC 3447 Appendix A.1.2.
         */
        exportPrivateKeyData(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            const outCapacity = this.exportedPrivateKeyDataLen(privateKey);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_export_private_key_data(this.ctxPtr, privateKey.ctxPtr, outCtxPtr);
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
         * Check if algorithm can encrypt data with a given key.
         */
        canEncrypt(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_can_encrypt(this.ctxPtr, publicKey.ctxPtr, dataLen);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Calculate required buffer length to hold the encrypted data.
         */
        encryptedLen(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_encrypted_len(this.ctxPtr, publicKey.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Encrypt data with a given public key.
         */
        encrypt(publicKey, data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
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

            const outCapacity = this.encryptedLen(publicKey, data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_encrypt(this.ctxPtr, publicKey.ctxPtr, dataCtxPtr, outCtxPtr);
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
         * Check if algorithm can decrypt data with a given key.
         * However, success result of decryption is not guaranteed.
         */
        canDecrypt(privateKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_can_decrypt(this.ctxPtr, privateKey.ctxPtr, dataLen);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Calculate required buffer length to hold the decrypted data.
         */
        decryptedLen(privateKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_decrypted_len(this.ctxPtr, privateKey.ctxPtr, dataLen);
            return proxyResult;
        }

        /**
         * Decrypt given data.
         */
        decrypt(privateKey, data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
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

            const outCapacity = this.decryptedLen(privateKey, data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_decrypt(this.ctxPtr, privateKey.ctxPtr, dataCtxPtr, outCtxPtr);
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
         * Check if algorithm can sign data digest with a given key.
         */
        canSign(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_can_sign(this.ctxPtr, privateKey.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return length in bytes required to hold signature.
         * Return zero if a given private key can not produce signatures.
         */
        signatureLen(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_signature_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Sign data digest with a given private key.
         */
        signHash(privateKey, hashId, digest) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('hashId', hashId);
            precondition.ensureByteArray('digest', digest);

            //  Copy bytes from JS memory to the WASM memory.
            const digestSize = digest.length * digest.BYTES_PER_ELEMENT;
            const digestPtr = Module._malloc(digestSize);
            Module.HEAP8.set(digest, digestPtr);

            //  Create C structure vsc_data_t.
            const digestCtxSize = Module._vsc_data_ctx_size();
            const digestCtxPtr = Module._malloc(digestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(digestCtxPtr, digestPtr, digestSize);

            const signatureCapacity = this.signatureLen(privateKey);
            const signatureCtxPtr = Module._vsc_buffer_new_with_capacity(signatureCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_sign_hash(this.ctxPtr, privateKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const signaturePtr = Module._vsc_buffer_bytes(signatureCtxPtr);
                const signaturePtrLen = Module._vsc_buffer_len(signatureCtxPtr);
                const signature = Module.HEAPU8.slice(signaturePtr, signaturePtr + signaturePtrLen);
                return signature;
            } finally {
                Module._free(digestPtr);
                Module._free(digestCtxPtr);
                Module._vsc_buffer_delete(signatureCtxPtr);
            }
        }

        /**
         * Check if algorithm can verify data digest with a given key.
         */
        canVerify(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_can_verify(this.ctxPtr, publicKey.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Verify data digest with a given public key and signature.
         */
        verifyHash(publicKey, hashId, digest, signature) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('hashId', hashId);
            precondition.ensureByteArray('digest', digest);
            precondition.ensureByteArray('signature', signature);

            //  Copy bytes from JS memory to the WASM memory.
            const digestSize = digest.length * digest.BYTES_PER_ELEMENT;
            const digestPtr = Module._malloc(digestSize);
            Module.HEAP8.set(digest, digestPtr);

            //  Create C structure vsc_data_t.
            const digestCtxSize = Module._vsc_data_ctx_size();
            const digestCtxPtr = Module._malloc(digestCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(digestCtxPtr, digestPtr, digestSize);

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
                proxyResult = Module._vscf_ed25519_verify_hash(this.ctxPtr, publicKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);

                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(digestPtr);
                Module._free(digestCtxPtr);
                Module._free(signaturePtr);
                Module._free(signatureCtxPtr);
            }
        }

        /**
         * Compute shared key for 2 asymmetric keys.
         * Note, computed shared key can be used only within symmetric cryptography.
         */
        computeSharedKey(publicKey, privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            const sharedKeyCapacity = this.sharedKeyLen(privateKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_compute_shared_key(this.ctxPtr, publicKey.ctxPtr, privateKey.ctxPtr, sharedKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const sharedKeyPtr = Module._vsc_buffer_bytes(sharedKeyCtxPtr);
                const sharedKeyPtrLen = Module._vsc_buffer_len(sharedKeyCtxPtr);
                const sharedKey = Module.HEAPU8.slice(sharedKeyPtr, sharedKeyPtr + sharedKeyPtrLen);
                return sharedKey;
            } finally {
                Module._vsc_buffer_delete(sharedKeyCtxPtr);
            }
        }

        /**
         * Return number of bytes required to hold shared key.
         * Expect Public Key or Private Key.
         */
        sharedKeyLen(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_shared_key_len(this.ctxPtr, key.ctxPtr);
            return proxyResult;
        }

        /**
         * Return length in bytes required to hold encapsulated shared key.
         */
        kemSharedKeyLen(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_kem_shared_key_len(this.ctxPtr, key.ctxPtr);
            return proxyResult;
        }

        /**
         * Return length in bytes required to hold encapsulated key.
         */
        kemEncapsulatedKeyLen(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_ed25519_kem_encapsulated_key_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        /**
         * Generate a shared key and a key encapsulated message.
         */
        kemEncapsulate(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);

            const sharedKeyCapacity = this.kemSharedKeyLen(publicKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);

            const encapsulatedKeyCapacity = this.encapsulatedKeyLen(publicKey);
            const encapsulatedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(encapsulatedKeyCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_kem_encapsulate(this.ctxPtr, publicKey.ctxPtr, sharedKeyCtxPtr, encapsulatedKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const sharedKeyPtr = Module._vsc_buffer_bytes(sharedKeyCtxPtr);
                const sharedKeyPtrLen = Module._vsc_buffer_len(sharedKeyCtxPtr);
                const sharedKey = Module.HEAPU8.slice(sharedKeyPtr, sharedKeyPtr + sharedKeyPtrLen);

                const encapsulatedKeyPtr = Module._vsc_buffer_bytes(encapsulatedKeyCtxPtr);
                const encapsulatedKeyPtrLen = Module._vsc_buffer_len(encapsulatedKeyCtxPtr);
                const encapsulatedKey = Module.HEAPU8.slice(encapsulatedKeyPtr, encapsulatedKeyPtr + encapsulatedKeyPtrLen);
                return { sharedKey, encapsulatedKey };
            } finally {
                Module._vsc_buffer_delete(sharedKeyCtxPtr);
                Module._vsc_buffer_delete(encapsulatedKeyCtxPtr);
            }
        }

        /**
         * Decapsulate the shared key.
         */
        kemDecapsulate(encapsulatedKey, privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('encapsulatedKey', encapsulatedKey);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);

            //  Copy bytes from JS memory to the WASM memory.
            const encapsulatedKeySize = encapsulatedKey.length * encapsulatedKey.BYTES_PER_ELEMENT;
            const encapsulatedKeyPtr = Module._malloc(encapsulatedKeySize);
            Module.HEAP8.set(encapsulatedKey, encapsulatedKeyPtr);

            //  Create C structure vsc_data_t.
            const encapsulatedKeyCtxSize = Module._vsc_data_ctx_size();
            const encapsulatedKeyCtxPtr = Module._malloc(encapsulatedKeyCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(encapsulatedKeyCtxPtr, encapsulatedKeyPtr, encapsulatedKeySize);

            const sharedKeyCapacity = this.kemSharedKeyLen(privateKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);

            try {
                const proxyResult = Module._vscf_ed25519_kem_decapsulate(this.ctxPtr, encapsulatedKeyCtxPtr, privateKey.ctxPtr, sharedKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);

                const sharedKeyPtr = Module._vsc_buffer_bytes(sharedKeyCtxPtr);
                const sharedKeyPtrLen = Module._vsc_buffer_len(sharedKeyCtxPtr);
                const sharedKey = Module.HEAPU8.slice(sharedKeyPtr, sharedKeyPtr + sharedKeyPtrLen);
                return sharedKey;
            } finally {
                Module._free(encapsulatedKeyPtr);
                Module._free(encapsulatedKeyCtxPtr);
                Module._vsc_buffer_delete(sharedKeyCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_ed25519_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Generate new private key.
         * Note, this operation might be slow.
         */
        generateKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_ed25519_generate_key(this.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return Ed25519;
};

module.exports = initEd25519;
