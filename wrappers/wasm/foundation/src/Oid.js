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

const initOid = (Module, modules) => {
    /**
     * Provide conversion logic between OID and algorithm tags.
     */
    class Oid {

        /**
         * Return OID for given algorithm identifier.
         */
        static fromAlgId(algId) {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_oid_from_alg_id(dataResultCtxPtr, algId);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Return algorithm identifier for given OID.
         */
        static toAlgId(oid) {
            // assert(typeof oid === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const oidSize = oid.length * oid.BYTES_PER_ELEMENT;
            const oidPtr = Module._malloc(oidSize);
            Module.HEAP8.set(oid, oidPtr);

            //  Create C structure vsc_data_t.
            const oidCtxSize = Module._vsc_data_ctx_size();
            const oidCtxPtr = Module._malloc(oidCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(oidCtxPtr, oidPtr, oidSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_oid_to_alg_id(oidCtxPtr);
                return proxyResult;
            } finally {
                Module._free(oidPtr);
                Module._free(oidCtxPtr);
            }
        }

        /**
         * Return OID for a given identifier.
         */
        static fromId(oidId) {
            //  Create C structure vsc_data_t.
            const dataResultCtxSize = Module._vsc_data_ctx_size();
            const dataResultCtxPtr = Module._malloc(dataResultCtxSize);

            try {
                Module._vscf_oid_from_id(dataResultCtxPtr, oidId);

                const dataResultSize = Module._vsc_data_len(dataResultCtxPtr);
                const dataResultPtr = Module._vsc_data_bytes(dataResultCtxPtr);
                const dataResult = Module.HEAPU8.slice(dataResultPtr, dataResultPtr + dataResultSize);
                return dataResult;
            } finally {
                Module._free(dataResultCtxPtr);
            }
        }

        /**
         * Return identifier for a given OID.
         */
        static toId(oid) {
            // assert(typeof oid === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const oidSize = oid.length * oid.BYTES_PER_ELEMENT;
            const oidPtr = Module._malloc(oidSize);
            Module.HEAP8.set(oid, oidPtr);

            //  Create C structure vsc_data_t.
            const oidCtxSize = Module._vsc_data_ctx_size();
            const oidCtxPtr = Module._malloc(oidCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(oidCtxPtr, oidPtr, oidSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_oid_to_id(oidCtxPtr);
                return proxyResult;
            } finally {
                Module._free(oidPtr);
                Module._free(oidCtxPtr);
            }
        }

        /**
         * Map oid identifier to the algorithm identifier.
         */
        static idToAlgId(oidId) {
            let proxyResult;
            proxyResult = Module._vscf_oid_id_to_alg_id(oidId);
            return proxyResult;
        }

        /**
         * Return true if given OIDs are equal.
         */
        static equal(lhs, rhs) {
            // assert(typeof lhs === 'Uint8Array')
            // assert(typeof rhs === 'Uint8Array')

            //  Copy bytes from JS memory to the WASM memory.
            const lhsSize = lhs.length * lhs.BYTES_PER_ELEMENT;
            const lhsPtr = Module._malloc(lhsSize);
            Module.HEAP8.set(lhs, lhsPtr);

            //  Create C structure vsc_data_t.
            const lhsCtxSize = Module._vsc_data_ctx_size();
            const lhsCtxPtr = Module._malloc(lhsCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(lhsCtxPtr, lhsPtr, lhsSize);

            //  Copy bytes from JS memory to the WASM memory.
            const rhsSize = rhs.length * rhs.BYTES_PER_ELEMENT;
            const rhsPtr = Module._malloc(rhsSize);
            Module.HEAP8.set(rhs, rhsPtr);

            //  Create C structure vsc_data_t.
            const rhsCtxSize = Module._vsc_data_ctx_size();
            const rhsCtxPtr = Module._malloc(rhsCtxSize);

            //  Point created vsc_data_t object to the copied bytes.
            Module._vsc_data(rhsCtxPtr, rhsPtr, rhsSize);

            let proxyResult;

            try {
                proxyResult = Module._vscf_oid_equal(lhsCtxPtr, rhsCtxPtr);

                const booleanResult = !!proxyResult;
                return booleanResult;
            } finally {
                Module._free(lhsPtr);
                Module._free(lhsCtxPtr);
                Module._free(rhsPtr);
                Module._free(rhsCtxPtr);
            }
        }
    }

    return Oid;
};

module.exports = initOid;
