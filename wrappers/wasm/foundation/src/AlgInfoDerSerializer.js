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


const initAlgInfoDerSerializer = (Module, modules) => {
    /**
     * Provide DER serializer of algorithm information.
     */
    class AlgInfoDerSerializer {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'AlgInfoDerSerializer';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_alg_info_der_serializer_new();
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
            return new AlgInfoDerSerializer(Module._vscf_alg_info_der_serializer_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new AlgInfoDerSerializer(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_alg_info_der_serializer_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        set asn1Writer(asn1Writer) {
            Module._vscf_alg_info_der_serializer_release_asn1_writer(this.ctxPtr)
            Module._vscf_alg_info_der_serializer_use_asn1_writer(this.ctxPtr, asn1Writer.ctxPtr)
        }

        /**
         * Return buffer size enough to hold serialized algorithm.
         */
        serializedLen(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialized_len(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }

        /**
         * Serialize algorithm info to buffer class.
         */
        serialize(algInfo) {
            const outSize = this.serializedLen(algInfo);
            const outCtxPtr = Module._vsc_buffer_new_with_capacity(outSize);

            try {
                Module._vscf_alg_info_der_serializer_serialize(this.ctxPtr, algInfo.ctxPtr, outCtxPtr);

                const outPtr = Module._vsc_buffer_bytes(outCtxPtr);
                const out = Module.HEAPU8.slice(outPtr, outPtr + outSize);
                return out;
            } finally {
                Module._vsc_buffer_delete(outCtxPtr);
            }
        }

        /**
         * Setup predefined values to the uninitialized class dependencies.
         */
        setupDefaults() {
            Module._vscf_alg_info_der_serializer_setup_defaults(this.ctxPtr);
        }

        /**
         * Serialize by using internal ASN.1 writer.
         * Note, that caller code is responsible to reset ASN.1 writer with
         * an output buffer.
         */
        serializeInplace(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_info_der_serializer_serialize_inplace(this.ctxPtr, algInfo.ctxPtr);
            return proxyResult;
        }
    }

    return AlgInfoDerSerializer;
};

module.exports = initAlgInfoDerSerializer;
