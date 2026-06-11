/**
 * Copyright (C) 2015-2026 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
        AES128_KW: 1,
        AES256_CBC: 2,
        AES256_GCM: 3,
        AES256_KW: 4,
        ALG_INFO_DER_DESERIALIZER: 5,
        ALG_INFO_DER_SERIALIZER: 6,
        ASN1RD: 7,
        ASN1WR: 8,
        CIPHER_ALG_INFO: 9,
        COMPOUND_KEY_ALG: 10,
        COMPOUND_KEY_ALG_INFO: 11,
        COMPOUND_PRIVATE_KEY: 12,
        COMPOUND_PUBLIC_KEY: 13,
        CTR_DRBG: 14,
        CURVE25519: 15,
        ECC: 16,
        ECC_ALG_INFO: 17,
        ECC_PRIVATE_KEY: 18,
        ECC_PUBLIC_KEY: 19,
        ED25519: 20,
        ENTROPY_ACCUMULATOR: 21,
        FAKE_RANDOM: 22,
        FALCON: 23,
        HASH_BASED_ALG_INFO: 24,
        HKDF: 25,
        HMAC: 26,
        HYBRID_KEY_ALG: 27,
        HYBRID_KEY_ALG_INFO: 28,
        HYBRID_PRIVATE_KEY: 29,
        HYBRID_PUBLIC_KEY: 30,
        KDF1: 31,
        KDF2: 32,
        KEY_ASN1_DESERIALIZER: 33,
        KEY_ASN1_SERIALIZER: 34,
        KEY_MATERIAL_RNG: 35,
        MESSAGE_INFO_DER_SERIALIZER: 36,
        ML_DSA: 37,
        ML_KEM: 38,
        PBE_ALG_INFO: 39,
        PKCS5_PBES2: 40,
        PKCS5_PBKDF2: 41,
        PKCS8_SERIALIZER: 42,
        RANDOM_PADDING: 43,
        RAW_PRIVATE_KEY: 44,
        RAW_PUBLIC_KEY: 45,
        RSA: 46,
        RSA_PRIVATE_KEY: 47,
        RSA_PUBLIC_KEY: 48,
        SALTED_KDF_ALG_INFO: 49,
        SEC1_SERIALIZER: 50,
        SEED_ENTROPY_SOURCE: 51,
        SHA224: 52,
        SHA256: 53,
        SHA384: 54,
        SHA512: 55,
        SIMPLE_ALG_INFO: 56,
    });

    return FoundationImplTag;
};

module.exports = initFoundationImplTag;
