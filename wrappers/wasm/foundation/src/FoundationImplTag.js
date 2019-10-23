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

        CIPHER_ALG_INFO: 7,

        COMPOUND_KEY_ALG: 8,

        COMPOUND_KEY_ALG_INFO: 9,

        COMPOUND_PRIVATE_KEY: 10,

        COMPOUND_PUBLIC_KEY: 11,

        CTR_DRBG: 12,

        CURVE25519: 13,

        ECC: 14,

        ECC_ALG_INFO: 15,

        ECC_PRIVATE_KEY: 16,

        ECC_PUBLIC_KEY: 17,

        ED25519: 18,

        ENTROPY_ACCUMULATOR: 19,

        FAKE_RANDOM: 20,

        FALCON: 21,

        HASH_BASED_ALG_INFO: 22,

        HKDF: 23,

        HMAC: 24,

        KDF1: 25,

        KDF2: 26,

        KEY_ASN1_DESERIALIZER: 27,

        KEY_ASN1_SERIALIZER: 28,

        KEY_MATERIAL_RNG: 29,

        MESSAGE_INFO_DER_SERIALIZER: 30,

        PBE_ALG_INFO: 31,

        PKCS5_PBES2: 32,

        PKCS5_PBKDF2: 33,

        PKCS8_SERIALIZER: 34,

        RAW_PRIVATE_KEY: 35,

        RAW_PUBLIC_KEY: 36,

        ROUND5: 37,

        RSA: 38,

        RSA_PRIVATE_KEY: 39,

        RSA_PUBLIC_KEY: 40,

        SALTED_KDF_ALG_INFO: 41,

        SEC1_SERIALIZER: 42,

        SEED_ENTROPY_SOURCE: 43,

        SHA224: 44,

        SHA256: 45,

        SHA384: 46,

        SHA512: 47,

        SIMPLE_ALG_INFO: 48
    });

    return FoundationImplTag;
};

module.exports = initFoundationImplTag;
