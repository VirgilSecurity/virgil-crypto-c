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

const initVerifier = (Module, modules) => {
    class Verifier {

        constructor(ctxPtr) {
            this.name = 'Verifier';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_verifier_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Verifier(Module._vscf_verifier_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new Verifier(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_verifier_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        reset(signature) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureByteArray('signature', signature);
            
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
                const proxyResult = Module._vscf_verifier_reset(this.ctxPtr, signatureCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            } finally {
                Module._free(signaturePtr);
                Module._free(signatureCtxPtr);
            }
        }

        appendData(data) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
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
            
            try {
                Module._vscf_verifier_append_data(this.ctxPtr, dataCtxPtr);
            } finally {
                Module._free(dataPtr);
                Module._free(dataCtxPtr);
            }
        }

        verify(publicKey) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('publicKey', publicKey, 'Foundation.PublicKey', modules.FoundationInterfaceTag.PUBLIC_KEY, modules.FoundationInterface);
            
            let proxyResult;
            proxyResult = Module._vscf_verifier_verify(this.ctxPtr, publicKey.ctxPtr);
            
            const booleanResult = !!proxyResult;
            return booleanResult;
        }

    }

    return Verifier;
};

module.exports = initVerifier;
