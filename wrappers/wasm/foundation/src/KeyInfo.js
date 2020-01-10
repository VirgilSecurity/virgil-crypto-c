/**
 * Copyright (C) 2015-2020 Virgil Security, Inc.
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

const initKeyInfo = (Module, modules) => {
    class KeyInfo {

        /**
         * Create object with underlying C context.
         *
         * Note. Parameter 'ctxPtr' SHOULD be passed from the generated code only.
         */
        constructor(ctxPtr) {
            this.name = 'KeyInfo';

            if (typeof ctxPtr === 'undefined') {
                this.ctxPtr = Module._vscf_key_info_new();
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
            return new KeyInfo(Module._vscf_key_info_shallow_copy(ctxPtr));
        }

        /**
         * Acquire C context by taking it ownership.
         *
         * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
         */
        static newAndTakeCContext(ctxPtr) {
            // assert(typeof ctxPtr === 'number');
            return new KeyInfo(ctxPtr);
        }

        /**
         * Release underlying C context.
         */
        delete() {
            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {
                Module._vscf_key_info_delete(this.ctxPtr);
                this.ctxPtr = null;
            }
        }

        /**
         * Build key information based on the generic algorithm information.
         */
        static newWithAlgInfo(algInfo) {
            precondition.ensureImplementInterface('algInfo', algInfo, 'Foundation.AlgInfo', modules.FoundationInterfaceTag.ALG_INFO, modules.FoundationInterface);

            let proxyResult;
            proxyResult = Module._vscf_key_info_new_with_alg_info(algInfo.ctxPtr);

            const jsResult = KeyInfo.newAndTakeCContext(proxyResult);
            return jsResult;
        }

        /**
         * Return true if a key is a compound key
         */
        isCompound() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_compound(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a hybrid key
         */
        isHybrid() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_hybrid(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key and compounds cipher key
         * and signer key are hybrid keys.
         */
        isCompoundHybrid() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_compound_hybrid(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key and compounds cipher key
         * is a hybrid key.
         */
        isCompoundHybridCipher() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_compound_hybrid_cipher(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key and compounds signer key
         * is a hybrid key.
         */
        isCompoundHybridSigner() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_compound_hybrid_signer(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key that contains hybrid keys
         * for encryption/decryption and signing/verifying that itself
         * contains a combination of classic keys and post-quantum keys.
         */
        isHybridPostQuantum() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_hybrid_post_quantum(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key that contains a hybrid key
         * for encryption/decryption that contains a classic key and
         * a post-quantum key.
         */
        isHybridPostQuantumCipher() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_hybrid_post_quantum_cipher(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return true if a key is a compound key that contains a hybrid key
         * for signing/verifying that contains a classic key and
         * a post-quantum key.
         */
        isHybridPostQuantumSigner() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_is_hybrid_post_quantum_signer(this.ctxPtr);

            const booleanResult = !!proxyResult;
            return booleanResult;
        }

        /**
         * Return common type of the key.
         */
        algId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return compound's cipher key id, if key is compound.
         * Return None, otherwise.
         */
        compoundCipherAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_cipher_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return compound's signer key id, if key is compound.
         * Return None, otherwise.
         */
        compoundSignerAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_signer_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's first key id, if key is hybrid.
         * Return None, otherwise.
         */
        hybridFirstKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_hybrid_first_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's second key id, if key is hybrid.
         * Return None, otherwise.
         */
        hybridSecondKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_hybrid_second_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's first key id of compound's cipher key,
         * if key is compound(hybrid, ...), None - otherwise.
         */
        compoundHybridCipherFirstKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_hybrid_cipher_first_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's second key id of compound's cipher key,
         * if key is compound(hybrid, ...), None - otherwise.
         */
        compoundHybridCipherSecondKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_hybrid_cipher_second_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's first key id of compound's signer key,
         * if key is compound(..., hybrid), None - otherwise.
         */
        compoundHybridSignerFirstKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_hybrid_signer_first_key_alg_id(this.ctxPtr);
            return proxyResult;
        }

        /**
         * Return hybrid's second key id of compound's signer key,
         * if key is compound(..., hybrid), None - otherwise.
         */
        compoundHybridSignerSecondKeyAlgId() {
            precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);

            let proxyResult;
            proxyResult = Module._vscf_key_info_compound_hybrid_signer_second_key_alg_id(this.ctxPtr);
            return proxyResult;
        }
    }

    return KeyInfo;
};

module.exports = initKeyInfo;
