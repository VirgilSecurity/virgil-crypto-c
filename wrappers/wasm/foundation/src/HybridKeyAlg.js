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

const initHybridKeyAlg = (Module, modules) => {
    class HybridKeyAlg {

        constructor(ctxPtr) {
            this.name = 'HybridKeyAlg';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_hybrid_key_alg_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new HybridKeyAlg(Module._vscf_hybrid_key_alg_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new HybridKeyAlg(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_hybrid_key_alg_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_hybrid_key_alg_release_random(this.ctxPtr)
            Module._vscf_hybrid_key_alg_use_random(this.ctxPtr, random.ctxPtr)
        }

        cipher(cipher) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('cipher', cipher, 'Foundation.CipherAuth', modules.FoundationInterfaceTag.CIPHER_AUTH, modules.FoundationInterface);
            Module._vscf_hybrid_key_alg_release_cipher(this.ctxPtr)
            Module._vscf_hybrid_key_alg_use_cipher(this.ctxPtr, cipher.ctxPtr)
        }

        hash(hash) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('hash', hash, 'Foundation.Hash', modules.FoundationInterfaceTag.HASH, modules.FoundationInterface);
            Module._vscf_hybrid_key_alg_release_hash(this.ctxPtr)
            Module._vscf_hybrid_key_alg_use_hash(this.ctxPtr, hash.ctxPtr)
        }

        static get CAN_IMPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_IMPORT_PUBLIC_KEY() {
            return true;
        }

        static get CAN_EXPORT_PUBLIC_KEY() {
            return true;
        }

        get CAN_EXPORT_PUBLIC_KEY() {
            return true;
        }

        static get CAN_IMPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_IMPORT_PRIVATE_KEY() {
            return true;
        }

        static get CAN_EXPORT_PRIVATE_KEY() {
            return true;
        }

        get CAN_EXPORT_PRIVATE_KEY() {
            return true;
        }

        generateEphemeralKey(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_hybrid_key_alg_generate_ephemeral_key(this.ctxPtr, key.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPublicKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPublicKey);
            const proxyResult = Module._vscf_hybrid_key_alg_import_public_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_hybrid_key_alg_export_public_key(this.ctxPtr, publicKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPrivateKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPrivateKey);
            const proxyResult = Module._vscf_hybrid_key_alg_import_private_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_hybrid_key_alg_export_private_key(this.ctxPtr, privateKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        canEncrypt(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_can_encrypt(this.ctxPtr, publicKey.ctxPtr, dataLen);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        encryptedLen(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_encrypted_len(this.ctxPtr, publicKey.ctxPtr, dataLen);
            return proxyResult;
        }

        encrypt(publicKey, data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
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
            
            const outCapacity = this.encryptedLen(publicKey, data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_hybrid_key_alg_encrypt(this.ctxPtr, publicKey.ctxPtr, dataCtxPtr, outCtxPtr);
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

        canDecrypt(privateKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_can_decrypt(this.ctxPtr, privateKey.ctxPtr, dataLen);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        decryptedLen(privateKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_decrypted_len(this.ctxPtr, privateKey.ctxPtr, dataLen);
            return proxyResult;
        }

        decrypt(privateKey, data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
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
            
            const outCapacity = this.decryptedLen(privateKey, data.length);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_hybrid_key_alg_decrypt(this.ctxPtr, privateKey.ctxPtr, dataCtxPtr, outCtxPtr);
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

        canSign(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_can_sign(this.ctxPtr, privateKey.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        signatureLen(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_signature_len(this.ctxPtr, privateKey.ctxPtr);
            return proxyResult;
        }

        signHash(privateKey, hashId, digest) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('digest', digest);
            
            // Copy bytes from JS memory to the WASM memory.
            const digestSize = digest.length * digest.BYTES_PER_ELEMENT;
            const digestPtr = Module._malloc(digestSize);
            Module.HEAP8.set(digest, digestPtr);
            
            // Create C structure vsc_data_t.
            const digestCtxSize = Module._vsc_data_ctx_size();
            const digestCtxPtr = Module._malloc(digestCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(digestCtxPtr, digestPtr, digestSize);
            
            const signatureCapacity = this.signatureLen(privateKey);
            const signatureCtxPtr = Module._vsc_buffer_new_with_capacity(signatureCapacity);
            
            try {
                const proxyResult = Module._vscf_hybrid_key_alg_sign_hash(this.ctxPtr, privateKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);
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

        canVerify(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_hybrid_key_alg_can_verify(this.ctxPtr, publicKey.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        verifyHash(publicKey, hashId, digest, signature) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureByteArray('digest', digest);
            precondition.ensureByteArray('signature', signature);
            
            // Copy bytes from JS memory to the WASM memory.
            const digestSize = digest.length * digest.BYTES_PER_ELEMENT;
            const digestPtr = Module._malloc(digestSize);
            Module.HEAP8.set(digest, digestPtr);
            
            // Create C structure vsc_data_t.
            const digestCtxSize = Module._vsc_data_ctx_size();
            const digestCtxPtr = Module._malloc(digestCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(digestCtxPtr, digestPtr, digestSize);
            
            // Copy bytes from JS memory to the WASM memory.
            const signatureSize = signature.length * signature.BYTES_PER_ELEMENT;
            const signaturePtr = Module._malloc(signatureSize);
            Module.HEAP8.set(signature, signaturePtr);
            
            // Create C structure vsc_data_t.
            const signatureCtxSize = Module._vsc_data_ctx_size();
            const signatureCtxPtr = Module._malloc(signatureCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(signatureCtxPtr, signaturePtr, signatureSize);
            
            try {
                const proxyResult = Module._vscf_hybrid_key_alg_verify_hash(this.ctxPtr, publicKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);
            
                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(digestPtr);
                Module._free(digestCtxPtr);
                Module._free(signaturePtr);
                Module._free(signatureCtxPtr);
            }
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_hybrid_key_alg_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        makeKey(firstKey, secondKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('firstKey', firstKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('secondKey', secondKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_hybrid_key_alg_make_key(this.ctxPtr, firstKey.ctxPtr, secondKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        static configCipher(cipher, hash, sharedKey) {
            precondition.ensureImplementInterface('cipher', cipher, 'Foundation.Cipher', modules.FoundationInterfaceTag.CIPHER, modules.FoundationInterface);
            precondition.ensureImplementInterface('hash', hash, 'Foundation.Hash', modules.FoundationInterfaceTag.HASH, modules.FoundationInterface);
            precondition.ensureByteArray('sharedKey', sharedKey);
            
            // Copy bytes from JS memory to the WASM memory.
            const sharedKeySize = sharedKey.length * sharedKey.BYTES_PER_ELEMENT;
            const sharedKeyPtr = Module._malloc(sharedKeySize);
            Module.HEAP8.set(sharedKey, sharedKeyPtr);
            
            // Create C structure vsc_data_t.
            const sharedKeyCtxSize = Module._vsc_data_ctx_size();
            const sharedKeyCtxPtr = Module._malloc(sharedKeyCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(sharedKeyCtxPtr, sharedKeyPtr, sharedKeySize);
            
            try {
                Module._vscf_hybrid_key_alg_config_cipher(cipher.ctxPtr, hash.ctxPtr, sharedKeyCtxPtr);
            } finally {
                Module._free(sharedKeyPtr);
                Module._free(sharedKeyCtxPtr);
            }
        }

    }

    return HybridKeyAlg;
};

module.exports = initHybridKeyAlg;
