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

const initHkdf = (Module, modules) => {
    class Hkdf {

        constructor(ctxPtr) {
            this.name = 'Hkdf';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_hkdf_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Hkdf(Module._vscf_hkdf_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Hkdf(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_hkdf_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set hash(hash) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('hash', hash, 'Foundation.Hash', modules.FoundationInterfaceTag.HASH, modules.FoundationInterface);
            Module._vscf_hkdf_release_hash(this.ctxPtr)
            Module._vscf_hkdf_use_hash(this.ctxPtr, hash.ctxPtr)
        }

        static get HASH_COUNTER_MAX() {
            return 255;
        }

        get HASH_COUNTER_MAX() {
            return 255;
        }

        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_hkdf_alg_id(this.ctxPtr);
            return proxyResult;
        }

        produceAlgInfo() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            
            let proxyResult;
            proxyResult = Module._vscf_hkdf_produce_alg_info(this.ctxPtr);
            
            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        restoreAlgInfo(algInfo) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);
            const proxyResult = Module._vscf_hkdf_restore_alg_info(this.ctxPtr, algInfo.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        derive(data, keyLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('data', data);
            precondition.ensureNumber('keyLen', keyLen);
            
            // Copy bytes from JS memory to the WASM memory.
            const dataSize = data.length * data.BYTES_PER_ELEMENT;
            const dataPtr = Module._malloc(dataSize);
            Module.HEAP8.set(data, dataPtr);
            
            // Create C structure vsc_data_t.
            const dataCtxSize = Module._vsc_data_ctx_size();
            const dataCtxPtr = Module._malloc(dataCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(dataCtxPtr, dataPtr, dataSize);
            
            const keyCapacity = keyLen;
            const keyCtxPtr = Module._vsc_buffer_new_with_capacity(keyCapacity);
            
            try {
                Module._vscf_hkdf_derive(this.ctxPtr, dataCtxPtr, keyLen, keyCtxPtr);
            
                const keyPtr = Module._vsc_buffer_bytes(keyCtxPtr);
                const keyPtrLen = Module._vsc_buffer_len(keyCtxPtr);
                const key = Module.HEAPU8.slice(keyPtr, keyPtr + keyPtrLen);
                return key;
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
                Module._vsc_buffer_delete(keyCtxPtr);
            }
        }

        reset(salt, iterationCount) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('salt', salt);
            precondition.ensureNumber('iterationCount', iterationCount);
            
            // Copy bytes from JS memory to the WASM memory.
            const saltSize = salt.length * salt.BYTES_PER_ELEMENT;
            const saltPtr = Module._malloc(saltSize);
            Module.HEAP8.set(salt, saltPtr);
            
            // Create C structure vsc_data_t.
            const saltCtxSize = Module._vsc_data_ctx_size();
            const saltCtxPtr = Module._malloc(saltCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(saltCtxPtr, saltPtr, saltSize);
            
            try {
                Module._vscf_hkdf_reset(this.ctxPtr, saltCtxPtr, iterationCount);
            } finally {
                Module._free(saltPtr);
                Module._free(saltCtxPtr);
            }
        }

        setInfo(info) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('info', info);
            
            // Copy bytes from JS memory to the WASM memory.
            const infoSize = info.length * info.BYTES_PER_ELEMENT;
            const infoPtr = Module._malloc(infoSize);
            Module.HEAP8.set(info, infoPtr);
            
            // Create C structure vsc_data_t.
            const infoCtxSize = Module._vsc_data_ctx_size();
            const infoCtxPtr = Module._malloc(infoCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(infoCtxPtr, infoPtr, infoSize);
            
            try {
                Module._vscf_hkdf_set_info(this.ctxPtr, infoCtxPtr);
            } finally {
                Module._free(infoPtr);
                Module._free(infoCtxPtr);
            }
        }

    }

    return Hkdf;
};

module.exports = initHkdf;
