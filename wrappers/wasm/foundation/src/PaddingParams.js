/**
 * Copyright (C) 2015-2019 Virgil Security, Inc.
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

const initPaddingParams = (Module, modules) => {
    /**
     * Handles padding parameters and constraints.
     */
    class PaddingParams {

        static get DEFAULT_FRAME() {
            return 160;
        }

        get DEFAULT_FRAME() {
            return PaddingParams.DEFAULT_FRAME;
        }

        static get DEFAULT_FRAME_MIN() {
            return 32;
        }

        get DEFAULT_FRAME_MIN() {
            return PaddingParams.DEFAULT_FRAME_MIN;
        }

        static get DEFAULT_FRAME_MAX() {
            return 8 * 1024;
        }

        get DEFAULT_FRAME_MAX() {
            return PaddingParams.DEFAULT_FRAME_MAX;
        }

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'PaddingParams';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_padding_params_new();
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
            return new PaddingParams(Module._vscf_padding_params_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new PaddingParams(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_padding_params_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Build padding params with given constraints.
         * Precondition: frame_length_min <= frame_length <= frame_length_max.
         * Next formula can clarify what frame is: "padding_length = data_length MOD frame"
         */
        static newWithConstraints(frame, frameMin, frameMax) {
            precondition.ensureNumber('frame', frame);
            precondition.ensureNumber('frameMin', frameMin);
            precondition.ensureNumber('frameMax', frameMax);

            let proxyResult;
            proxyResult = Module._vscf_padding_params_new_with_constraints(frame, frameMin, frameMax);

            const jsResult = PaddingParams.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return padding frame in bytes.
         */
        frame() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_params_frame(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return minimum padding frame in bytes.
         */
        frameMin() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_params_frame_min(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return minimum padding frame in bytes.
         */
        frameMax() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_padding_params_frame_max(this.ctxPtr);
            return proxyResult;
        }
    }

    return PaddingParams;
};

module.exports = initPaddingParams;
