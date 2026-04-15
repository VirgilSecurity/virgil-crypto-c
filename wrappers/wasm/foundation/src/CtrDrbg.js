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

const initCtrDrbg = (Module, modules) => {
    class CtrDrbg {

        constructor(ctxPtr) {
            this.name = 'CtrDrbg';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_ctr_drbg_new();
            } else {
                this.ctxPtr = ctxPtr;
            }
        }

        static newAndUseCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new CtrDrbg(Module._vscf_ctr_drbg_shallow_copy(ctxPtr));
        }

        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new CtrDrbg(ctxPtr);
        }

        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_ctr_drbg_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        entropySource(entropySource) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('entropySource', entropySource, 'Foundation.EntropySource', modules.FoundationInterfaceTag.ENTROPY_SOURCE, modules.FoundationInterface);
            Module._vscf_ctr_drbg_release_entropy_source(this.ctxPtr)
            Module._vscf_ctr_drbg_use_entropy_source(this.ctxPtr, entropySource.ctxPtr)
        }

        static get RESEED_INTERVAL() {
            return 10000;
        }

        get RESEED_INTERVAL() {
            return 10000;
        }

        static get ENTROPY_LEN() {
            return 48;
        }

        get ENTROPY_LEN() {
            return 48;
        }

        random(dataLen) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('dataLen', dataLen);
            
            const dataCapacity = dataLen;
            const dataCtxPtr = Module._vsc_buffer_new_with_capacity(dataCapacity);
            
            try {
                const proxyResult = Module._vscf_ctr_drbg_random(this.ctxPtr, dataLen, dataCtxPtr);
                modules.FoundationError.handleStatusCode(proxyResult);
            
                const dataPtr = Module._vsc_buffer_bytes(dataCtxPtr);
                const dataPtrLen = Module._vsc_buffer_len(dataCtxPtr);
                const data = Module.HEAPU8.slice(dataPtr, dataPtr + dataPtrLen);
                return data;
            } finally {
                Module._vsc_buffer_delete(dataCtxPtr);
            }
        }

        reseed() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_ctr_drbg_reseed(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_ctr_drbg_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        enablePredictionResistance() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_ctr_drbg_enable_prediction_resistance(this.ctxPtr);
        }

        setReseedInterval(interval) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('interval', interval);
            Module._vscf_ctr_drbg_set_reseed_interval(this.ctxPtr, interval);
        }

        setEntropyLen(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);
            Module._vscf_ctr_drbg_set_entropy_len(this.ctxPtr, len);
        }

    }

    return CtrDrbg;
};

module.exports = initCtrDrbg;
