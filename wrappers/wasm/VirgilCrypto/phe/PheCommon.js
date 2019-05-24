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


const initPheCommon = (Module, modules) => {
    class PheCommon {

        /**
         * PHE elliptic curve point binary length
         */
        static get PHE_POINT_LENGTH() {
            return 65;
        }

        get PHE_POINT_LENGTH() {
            return PheCommon.PHE_POINT_LENGTH;
        }

        /**
         * PHE max password length
         */
        static get PHE_MAX_PASSWORD_LENGTH() {
            return 128;
        }

        get PHE_MAX_PASSWORD_LENGTH() {
            return PheCommon.PHE_MAX_PASSWORD_LENGTH;
        }

        /**
         * PHE server identifier length
         */
        static get PHE_SERVER_IDENTIFIER_LENGTH() {
            return 32;
        }

        get PHE_SERVER_IDENTIFIER_LENGTH() {
            return PheCommon.PHE_SERVER_IDENTIFIER_LENGTH;
        }

        /**
         * PHE client identifier length
         */
        static get PHE_CLIENT_IDENTIFIER_LENGTH() {
            return 32;
        }

        get PHE_CLIENT_IDENTIFIER_LENGTH() {
            return PheCommon.PHE_CLIENT_IDENTIFIER_LENGTH;
        }

        /**
         * PHE account key length
         */
        static get PHE_ACCOUNT_KEY_LENGTH() {
            return 32;
        }

        get PHE_ACCOUNT_KEY_LENGTH() {
            return PheCommon.PHE_ACCOUNT_KEY_LENGTH;
        }

        /**
         * PHE private key length
         */
        static get PHE_PRIVATE_KEY_LENGTH() {
            return 32;
        }

        get PHE_PRIVATE_KEY_LENGTH() {
            return PheCommon.PHE_PRIVATE_KEY_LENGTH;
        }

        /**
         * PHE public key length
         */
        static get PHE_PUBLIC_KEY_LENGTH() {
            return 65;
        }

        get PHE_PUBLIC_KEY_LENGTH() {
            return PheCommon.PHE_PUBLIC_KEY_LENGTH;
        }

        /**
         * PHE hash length
         */
        static get PHE_HASH_LEN() {
            return 32;
        }

        get PHE_HASH_LEN() {
            return PheCommon.PHE_HASH_LEN;
        }

        /**
         * Maximum data size to encrypt
         */
        static get PHE_MAX_ENCRYPT_LEN() {
            return 1024 * 1024 - 64;
        }

        get PHE_MAX_ENCRYPT_LEN() {
            return PheCommon.PHE_MAX_ENCRYPT_LEN;
        }

        /**
         * Maximum data size to decrypt
         */
        static get PHE_MAX_DECRYPT_LEN() {
            return 1024 * 1024;
        }

        get PHE_MAX_DECRYPT_LEN() {
            return PheCommon.PHE_MAX_DECRYPT_LEN;
        }
    }

    return PheCommon;
};

module.exports = initPheCommon;
