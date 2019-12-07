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


const initFoundationImplTag = (Module, modules) => {
    const FoundationImplTag = Object.freeze({

        AES256_CBC: 1,

        AES256_GCM: 2,

        ALG_INFO_DER_DESERIALIZER: 3,

        ALG_INFO_DER_SERIALIZER: 4,

        ASN1RD: 5,

        ASN1WR: 6,

        CHAINED_KEY_ALG: 7,

        CHAINED_KEY_ALG_INFO: 8,

        CHAINED_PRIVATE_KEY: 9,

        CHAINED_PUBLIC_KEY: 10,

        CIPHER_ALG_INFO: 11,

        COMPOUND_KEY_ALG: 12,

        COMPOUND_KEY_ALG_INFO: 13,

        COMPOUND_PRIVATE_KEY: 14,

        COMPOUND_PUBLIC_KEY: 15,

        CTR_DRBG: 16,

        CURVE25519: 17,

        ECC: 18,

        ECC_ALG_INFO: 19,

        ECC_PRIVATE_KEY: 20,

        ECC_PUBLIC_KEY: 21,

        ED25519: 22,

        ENTROPY_ACCUMULATOR: 23,

        FAKE_RANDOM: 24,

        FALCON: 25,

        HASH_BASED_ALG_INFO: 26,

        HKDF: 27,

        HMAC: 28,

        KDF1: 29,

        KDF2: 30,

        KEY_ASN1_DESERIALIZER: 31,

        KEY_ASN1_SERIALIZER: 32,

        KEY_MATERIAL_RNG: 33,

        MESSAGE_INFO_DER_SERIALIZER: 34,

        PADDING_CIPHER: 35,

        PBE_ALG_INFO: 36,

        PKCS5_PBES2: 37,

        PKCS5_PBKDF2: 38,

        PKCS8_SERIALIZER: 39,

        RANDOM_PADDING: 40,

        RAW_PRIVATE_KEY: 41,

        RAW_PUBLIC_KEY: 42,

        ROUND5: 43,

        RSA: 44,

        RSA_PRIVATE_KEY: 45,

        RSA_PUBLIC_KEY: 46,

        SALTED_KDF_ALG_INFO: 47,

        SEC1_SERIALIZER: 48,

        SEED_ENTROPY_SOURCE: 49,

        SHA224: 50,

        SHA256: 51,

        SHA384: 52,

        SHA512: 53,

        SIMPLE_ALG_INFO: 54
    });

    return FoundationImplTag;
};

module.exports = initFoundationImplTag;
