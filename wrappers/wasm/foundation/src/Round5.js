/**
 * Copyright (C) 2015-2026 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

const initRound5 = (Module, modules) => {
    class Round5 {

        constructor(ctxPtr) {
            this.name = 'Round5';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_round5_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Round5(Module._vscf_round5_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Round5(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_round5_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_round5_release_random(this.ctxPtr)
            Module._vscf_round5_use_random(this.ctxPtr, random.ctxPtr)
        }

        static get SEED_LEN() {
            return 48;
        }

        get SEED_LEN() {
            return 48;
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
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_generate_ephemeral_key(this.ctxPtr, key.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        importPublicKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPublicKey);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_import_public_key(this.ctxPtr, rawKey.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        exportPublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_export_public_key(this.ctxPtr, publicKey.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.RawPublicKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        importPrivateKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPrivateKey);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_import_private_key(this.ctxPtr, rawKey.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        exportPrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_export_private_key(this.ctxPtr, privateKey.ctxPtr, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.RawPrivateKey.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        kemSharedKeyLen(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_round5_kem_shared_key_len(this.ctxPtr, key.ctxPtr);
            return proxyResult;
        }

        kemEncapsulatedKeyLen(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_round5_kem_encapsulated_key_len(this.ctxPtr, publicKey.ctxPtr);
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
                const proxyResult = Module._vscf_round5_kem_encapsulate(this.ctxPtr, publicKey.ctxPtr, sharedKeyCtxPtr, encapsulatedKeyCtxPtr);
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
                const proxyResult = Module._vscf_round5_kem_decapsulate(this.ctxPtr, encapsulatedKeyCtxPtr, privateKey.ctxPtr, sharedKeyCtxPtr);
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
            const proxyResult = Module._vscf_round5_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateKey(algId) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);
            
            let proxyResult;
            
            try {
                proxyResult = Module._vscf_round5_generate_key(this.ctxPtr, algId, errorCtxPtr);
            
                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);
            
                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

    }

    return Round5;
};

module.exports = initRound5;
