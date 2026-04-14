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

const initFalcon = (Module, modules) => {
    class Falcon {

        constructor(ctxPtr) {
            this.name = 'Falcon';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_falcon_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Falcon(Module._vscf_falcon_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Falcon(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_falcon_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_falcon_release_random(this.ctxPtr)
            Module._vscf_falcon_use_random(this.ctxPtr, random.ctxPtr)
        }

        static get SEED_LEN() {
            return 48;
        }

        get SEED_LEN() {
            return 48;
        }

        static get LOGN_512() {
            return 9;
        }

        get LOGN_512() {
            return 9;
        }

        static get LOGN_1024() {
            return 10;
        }

        get LOGN_1024() {
            return 10;
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

        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_falcon_alg_id(this.ctxPtr);
            return proxyResult;
        }

        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_falcon_produce_alg_info(this.ctxPtr);
            
            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_falcon_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateEphemeralKey(key) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('key', key, 'Foundation.Key', modules.FoundationInterfaceTag.KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_falcon_generate_ephemeral_key(this.ctxPtr, key.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPublicKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPublicKey);
            const proxyResult = Module._vscf_falcon_import_public_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPublicKey(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_falcon_export_public_key(this.ctxPtr, publicKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        importPrivateKey(rawKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureClass('rawKey', rawKey, modules.RawPrivateKey);
            const proxyResult = Module._vscf_falcon_import_private_key(this.ctxPtr, rawKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        exportPrivateKey(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            const proxyResult = Module._vscf_falcon_export_private_key(this.ctxPtr, privateKey.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        canSign(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_falcon_can_sign(this.ctxPtr, privateKey.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        signatureLen(privateKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('privateKey', privateKey, 'Foundation.PrivateKey', modules.FoundationInterfaceTag.PRIVATE_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_falcon_signature_len(this.ctxPtr, privateKey.ctxPtr);
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
                const proxyResult = Module._vscf_falcon_sign_hash(this.ctxPtr, privateKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);
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
            proxyResult = Module._vscf_falcon_can_verify(this.ctxPtr, publicKey.ctxPtr);
            
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
                const proxyResult = Module._vscf_falcon_verify_hash(this.ctxPtr, publicKey.ctxPtr, hashId, digestCtxPtr, signatureCtxPtr);
            
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
            const proxyResult = Module._vscf_falcon_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        generateKey() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_falcon_generate_key(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

    }

    return Falcon;
};

module.exports = initFalcon;
