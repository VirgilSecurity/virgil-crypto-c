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
    /**
     * Implementation of the RNG using deterministic random bit generators
     * based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
     * This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
     */
    class CtrDrbg {

        /**
         * The interval before reseed is performed by default.
         */
        static get RESEED_INTERVAL() {
            return 10000;
        }

        get RESEED_INTERVAL() {
            return CtrDrbg.RESEED_INTERVAL;
        }

        /**
         * The amount of entropy used per seed by default.
         */
        static get ENTROPY_LEN() {
            return 48;
        }

        get ENTROPY_LEN() {
            return CtrDrbg.ENTROPY_LEN;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'CtrDrbg';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_ctr_drbg_new();
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
            return new CtrDrbg(Module._vscf_ctr_drbg_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new CtrDrbg(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_ctr_drbg_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set entropySource(entropySource) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureImplementInterface('entropySource', entropySource, 'Foundation.EntropySource', modules.FoundationInterfaceTag.ENTROPY_SOURCE, modules.FoundationInterface);
            Module._vscf_ctr_drbg_release_entropy_source(this.ctxPtr)
            const proxyStatus = Module._vscf_ctr_drbg_use_entropy_source(this.ctxPtr, entropySource.ctxPtr)
            modules.FoundationError.handleStatusCode(proxyStatus)
        }

        /**
         * Generate random bytes.
         * All RNG implementations must be thread-safe.
         */
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

        /**
         * Retrieve new seed data from the entropy sources.
         */
        reseed() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_ctr_drbg_reseed(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            const proxyResult = Module._vscf_ctr_drbg_setup_defaults(this.ctxPtr);
            modules.FoundationError.handleStatusCode(proxyResult);
        }

        /**
         * Force entropy to be gathered at the beginning of every call to
         * the random() method.
         * Note, use this if your entropy source has sufficient throughput.
         */
        enablePredictionResistance() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            Module._vscf_ctr_drbg_enable_prediction_resistance(this.ctxPtr);
        }

        /**
         * Sets the reseed interval.
         * Default value is reseed interval.
         */
        setReseedInterval(interval) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('interval', interval);
            Module._vscf_ctr_drbg_set_reseed_interval(this.ctxPtr, interval);
        }

        /**
         * Sets the amount of entropy grabbed on each seed or reseed.
         * The default value is entropy len.
         */
        setEntropyLen(len) {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);
            precondition.ensureNumber('len', len);
            Module._vscf_ctr_drbg_set_entropy_len(this.ctxPtr, len);
        }
    }

    return CtrDrbg;
};

module.exports = initCtrDrbg;
