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

const initShamir = (Module, modules) => {
    class Shamir {

        constructor(ctxPtr) {
            this.name = 'Shamir';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_shamir_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Shamir(Module._vscf_shamir_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Shamir(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_shamir_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set random(random) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('random', random, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vscf_shamir_release_random(this.ctxPtr)
            Module._vscf_shamir_use_random(this.ctxPtr, random.ctxPtr)
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_shamir_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        static shareLen(secretLen) {
            precondition.ensureNumber('secretLen', secretLen);
            
            let proxyResult;
            proxyResult = Module._vscf_shamir_share_len(secretLen);
            return proxyResult;
        }

        shareLen(secretLen) {
            return Shamir.shareLen(secretLen);
        }

        static sharesLen(secretLen, shareCount) {
            precondition.ensureNumber('secretLen', secretLen);
            precondition.ensureNumber('shareCount', shareCount);
            
            let proxyResult;
            proxyResult = Module._vscf_shamir_shares_len(secretLen, shareCount);
            return proxyResult;
        }

        sharesLen(secretLen, shareCount) {
            return Shamir.sharesLen(secretLen, shareCount);
        }

        static recoveredSecretLen(sharesLen, shareCount) {
            precondition.ensureNumber('sharesLen', sharesLen);
            precondition.ensureNumber('shareCount', shareCount);
            
            let proxyResult;
            proxyResult = Module._vscf_shamir_recovered_secret_len(sharesLen, shareCount);
            return proxyResult;
        }

        recoveredSecretLen(sharesLen, shareCount) {
            return Shamir.recoveredSecretLen(sharesLen, shareCount);
        }

        split(secret, threshold, shareCount) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('secret', secret);
            precondition.ensureNumber('threshold', threshold);
            precondition.ensureNumber('shareCount', shareCount);
            
            // Copy bytes from JS memory to the WASM memory.
            const secretSize = secret.length * secret.BYTES_PER_ELEMENT;
            const secretPtr = Module._malloc(secretSize);
            Module.HEAP8.set(secret, secretPtr);
            
            // Create C structure vsc_data_t.
            const secretCtxSize = Module._vsc_data_ctx_size();
            const secretCtxPtr = Module._malloc(secretCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(secretCtxPtr, secretPtr, secretSize);
            
            const outCapacity = this.sharesLen(secret.length, shareCount);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outCapacity);
            
            try {
                const proxyResult = Module._vscf_shamir_split(this.ctxPtr, secretCtxPtr, threshold, shareCount, outCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const outPtrLen = Module._vsc_buffer_len(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outPtrLen);
                return out;
            } finally {
                Module._free(secretPtr);
                Module._free(secretCtxPtr);
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        combine(shares, shareCount) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('shares', shares);
            precondition.ensureNumber('shareCount', shareCount);
            
            // Copy bytes from JS memory to the WASM memory.
            const sharesSize = shares.length * shares.BYTES_PER_ELEMENT;
            const sharesPtr = Module._malloc(sharesSize);
            Module.HEAP8.set(shares, sharesPtr);
            
            // Create C structure vsc_data_t.
            const sharesCtxSize = Module._vsc_data_ctx_size();
            const sharesCtxPtr = Module._malloc(sharesCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(sharesCtxPtr, sharesPtr, sharesSize);
            
            const secretCapacity = this.recoveredSecretLen(shares.length, shareCount);
            const secretCtxPtr = Module._vsc_buffer_new_with_capacity(secretCapacity);
            
            try {
                const proxyResult = Module._vscf_shamir_combine(this.ctxPtr, sharesCtxPtr, shareCount, secretCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const secretPtr = Module._vsc_buffer_bytes(secretCtxPtr);
                const secretPtrLen = Module._vsc_buffer_len(secretCtxPtr);
                const secret = Module.HEAPU8.slice(secretPtr, secretPtr + secretPtrLen);
                return secret;
            } finally {
                Module._free(sharesPtr);
                Module._free(sharesCtxPtr);
                Module._vsc_buffer_delete(secretCtxPtr);
            }
        }

    }

    return Shamir;
};

module.exports = initShamir;
