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


const initAlgFactory = (Module, modules) => {
    /**
     * Create algorithms based on the given information.
     */
    class AlgFactory {

        /**
         * Create algorithm that implements "hash stream" interface.
         */
        static createHashFromInfo(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_factory_create_hash_from_info(algInfo.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Create algorithm that implements "mac stream" interface.
         */
        static createMacFromInfo(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_factory_create_mac_from_info(algInfo.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Create algorithm that implements "kdf" interface.
         */
        static createKdfFromInfo(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_factory_create_kdf_from_info(algInfo.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Create algorithm that implements "salted kdf" interface.
         */
        static createSaltedKdfFromInfo(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_factory_create_salted_kdf_from_info(algInfo.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Create algorithm that implements "cipher" interface.
         */
        static createCipherFromInfo(algInfo) {
            let proxyResult;
            proxyResult = Module._vscf_alg_factory_create_cipher_from_info(algInfo.ctxPtr);

            const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Create algorithm that implements "public key" interface.
         */
        static createPublicKeyFromRawKey(rawKey) {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_alg_factory_create_public_key_from_raw_key(rawKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }

        /**
         * Create algorithm that implements "private key" interface.
         */
        static createPrivateKeyFromRawKey(rawKey) {
            const errorCtxSize = Module._vscf_error_ctx_size();
            const errorCtxPtr = Module._malloc(errorCtxSize);
            Module._vscf_error_reset(errorCtxPtr);

            let proxyResult;

            try {
                proxyResult = Module._vscf_alg_factory_create_private_key_from_raw_key(rawKey.ctxPtr, errorCtxPtr);

                const errorStatus = Module._vscf_error_status(errorCtxPtr);
                modules.FoundationError.handleStatusCode(errorStatus);

                const jsResult = modules.FoundationInterface.newAndTakeCContext(proxyResult);
                return jsResult;
            } finally {
                Module._free(errorCtxPtr);
            }
        }
    }

    return AlgFactory;
};

module.exports = initAlgFactory;
