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

const initUokmsWrapRotation = (Module, modules) => {
    class UokmsWrapRotation {

        constructor(ctxPtr) {
            this.name = 'UokmsWrapRotation';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vsce_uokms_wrap_rotation_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new UokmsWrapRotation(Module._vsce_uokms_wrap_rotation_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new UokmsWrapRotation(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vsce_uokms_wrap_rotation_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        operationRandom(operationRandom) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('operationRandom', operationRandom, 'Foundation.Random', modules.FoundationInterfaceTag.RANDOM, modules.FoundationInterface);
            Module._vsce_uokms_wrap_rotation_release_operation_random(this.ctxPtr)
            Module._vsce_uokms_wrap_rotation_use_operation_random(this.ctxPtr, operationRandom.ctxPtr)
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vsce_uokms_wrap_rotation_setup_defaults(this.ctxPtr);
            modules.PheError.handleStatusCode(proxyResult);
        }

        setUpdateToken(updateToken) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('updateToken', updateToken);
            
            // Copy bytes from JS memory to the WASM memory.
            const updateTokenSize = updateToken.length * updateToken.BYTES_PER_ELEMENT;
            const updateTokenPtr = Module._malloc(updateTokenSize);
            Module.HEAP8.set(updateToken, updateTokenPtr);
            
            // Create C structure vsc_data_t.
            const updateTokenCtxSize = Module._vsc_data_ctx_size();
            const updateTokenCtxPtr = Module._malloc(updateTokenCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(updateTokenCtxPtr, updateTokenPtr, updateTokenSize);
            
            try {
                const proxyResult = Module._vsce_uokms_wrap_rotation_set_update_token(this.ctxPtr, updateTokenCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);
            } finally {
                Module._free(updateTokenPtr);
                Module._free(updateTokenCtxPtr);
            }
        }

        updateWrap(wrap) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('wrap', wrap);
            
            // Copy bytes from JS memory to the WASM memory.
            const wrapSize = wrap.length * wrap.BYTES_PER_ELEMENT;
            const wrapPtr = Module._malloc(wrapSize);
            Module.HEAP8.set(wrap, wrapPtr);
            
            // Create C structure vsc_data_t.
            const wrapCtxSize = Module._vsc_data_ctx_size();
            const wrapCtxPtr = Module._malloc(wrapCtxSize);
            
            // Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(wrapCtxPtr, wrapPtr, wrapSize);
            
            const newWrapCapacity = modules.PheCommon.PHE_PUBLIC_KEY_LENGTH;
            const newWrapCtxPtr = Module._vsc_buffer_new_with_capacity(newWrapCapacity);
            
            try {
                const proxyResult = Module._vsce_uokms_wrap_rotation_update_wrap(this.ctxPtr, wrapCtxPtr, newWrapCtxPtr);
                modules.PheError.handleStatusCode(proxyResult);
            
                const newWrapPtr = Module._vsc_buffer_bytes(newWrapCtxPtr);
                const newWrapPtrLen = Module._vsc_buffer_len(newWrapCtxPtr);
                const newWrap = Module.HEAPU8.slice(newWrapPtr, newWrapPtr + newWrapPtrLen);
                return newWrap;
            } finally {
                Module._free(wrapPtr);
                Module._free(wrapCtxPtr);
                Module._vsc_buffer_delete(newWrapCtxPtr);
            }
        }

    }

    return UokmsWrapRotation;
};

module.exports = initUokmsWrapRotation;
