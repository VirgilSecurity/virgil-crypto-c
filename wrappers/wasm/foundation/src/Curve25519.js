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

const initCurve25519 = (Module, modules) => {
    class Curve25519 {

        constructor(ctxPtr) {
            this.name = 'Curve25519';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_curve25519_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Curve25519(Module._vscf_curve25519_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Curve25519(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_curve25519_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_curve25519_release_random(this.ctxPtr)
            Module._vscf_curve25519_use_random(this.ctxPtr, random.ctxPtr)
        }

        ecies(ecies) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('ecies', ecies, modules.Ecies);
            Module._vscf_curve25519_release_ecies(this.ctxPtr)
            Module._vscf_curve25519_use_ecies(this.ctxPtr, ecies.ctxPtr)
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
            const proxyResult = Module._vscf_curve25519_generate_ephemeral_key(this.ctxPtr, key.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPublicKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPublicKey);
            const proxyResult = Module._vscf_curve25519_import_public_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_curve25519_export_public_key(this.ctxPtr, publicKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPrivateKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPrivateKey);
            const proxyResult = Module._vscf_curve25519_import_private_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_curve25519_export_private_key(this.ctxPtr, privateKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        canEncrypt(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_can_encrypt(this.ctxPtr, publicKey.ctxPtr, dataLen);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        encryptedLen(publicKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_encrypted_len(this.ctxPtr, publicKey.ctxPtr, dataLen);
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
                const proxyResult = Module._vscf_curve25519_encrypt(this.ctxPtr, publicKey.ctxPtr, dataCtxPtr, outCtxPtr);
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
            proxyResult = Module._vscf_curve25519_can_decrypt(this.ctxPtr, privateKey.ctxPtr, dataLen);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        decryptedLen(privateKey, dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            precondition.ensureNumber('dataLen', dataLen);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_decrypted_len(this.ctxPtr, privateKey.ctxPtr, dataLen);
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
                const proxyResult = Module._vscf_curve25519_decrypt(this.ctxPtr, privateKey.ctxPtr, dataCtxPtr, outCtxPtr);
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

        computeSharedKey(publicKey, privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            const sharedKeyCapacity = this.sharedKeyLen(privateKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);
            
            try {
                const proxyResult = Module._vscf_curve25519_compute_shared_key(this.ctxPtr, publicKey.ctxPtr, privateKey.ctxPtr, sharedKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const sharedKeyPtr = Module._vsc_buffer_bytes(sharedKeyCtxPtr);
                const sharedKeyPtrLen = Module._vsc_buffer_len(sharedKeyCtxPtr);
                const sharedKey = Module.HEAPU8.slice(sharedKeyPtr, sharedKeyPtr + sharedKeyPtrLen);
                return sharedKey;
            } finally {
                Module._vsc_buffer_delete(sharedKeyCtxPtr);
            }
        }

        sharedKeyLen(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_shared_key_len(this.ctxPtr, key.ctxPtr);
            return proxyResult;
        }

        kemSharedKeyLen(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_kem_shared_key_len(this.ctxPtr, key.ctxPtr);
            return proxyResult;
        }

        kemEncapsulatedKeyLen(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_curve25519_kem_encapsulated_key_len(this.ctxPtr, publicKey.ctxPtr);
            return proxyResult;
        }

        kemEncapsulate(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            const sharedKeyCapacity = this.kemSharedKeyLen(publicKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);
            
            const encapsulatedKeyCapacity = this.kemEncapsulatedKeyLen(publicKey);
            const encapsulatedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(encapsulatedKeyCapacity);
            
            try {
                const proxyResult = Module._vscf_curve25519_kem_encapsulate(this.ctxPtr, publicKey.ctxPtr, sharedKeyCtxPtr, encapsulatedKeyCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const sharedKeyPtr = Module._vsc_buffer_bytes(sharedKeyCtxPtr);
                const sharedKeyPtrLen = Module._vsc_buffer_len(sharedKeyCtxPtr);
                const sharedKey = Module.HEAPU8.slice(sharedKeyPtr, sharedKeyPtr + sharedKeyPtrLen);
            
                const encapsulatedKeyPtr = Module._vsc_buffer_bytes(encapsulatedKeyCtxPtr);
                const encapsulatedKeyPtrLen = Module._vsc_buffer_len(encapsulatedKeyCtxPtr);
                const encapsulatedKey = Module.HEAPU8.slice(encapsulatedKeyPtr, encapsulatedKeyPtr + encapsulatedKeyPtrLen);
                return sharedKey;
            } finally {
                Module._vsc_buffer_delete(sharedKeyCtxPtr);
                Module._vsc_buffer_delete(encapsulatedKeyCtxPtr);
            }
        }

        kemDecapsulate(encapsulatedKey, privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('encapsulatedKey', encapsulatedKey);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            // Copy bytes from JS memory to the WASM memory.
            const encapsulatedKeySize = encapsulatedKey.length * encapsulatedKey.BYTES_PER_ELEMENT;
            const encapsulatedKeyPtr = Module._malloc(encapsulatedKeySize);
            Module.HEAP8.set(encapsulatedKey, encapsulatedKeyPtr);
            
            // Create C structure vsc_data_t.
            const encapsulatedKeyCtxSize = Module._vsc_data_ctx_size();
            const encapsulatedKeyCtxPtr = Module._malloc(encapsulatedKeyCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(encapsulatedKeyCtxPtr, encapsulatedKeyPtr, encapsulatedKeySize);
            
            const sharedKeyCapacity = this.kemSharedKeyLen(privateKey);
            const sharedKeyCtxPtr = Module._vsc_buffer_new_with_capacity(sharedKeyCapacity);
            
            try {
                const proxyResult = Module._vscf_curve25519_kem_decapsulate(this.ctxPtr, encapsulatedKeyCtxPtr, privateKey.ctxPtr, sharedKeyCtxPtr);
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

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_curve25519_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_curve25519_generate_key(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

    }

    return Curve25519;
};

module.exports = initCurve25519;
