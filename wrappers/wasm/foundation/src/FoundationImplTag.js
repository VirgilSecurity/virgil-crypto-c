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
        CHUNKED_ALG_INFO: 9,
        CIPHER_ALG_INFO: 10,
        COMPOUND_KEY_ALG: 11,
        COMPOUND_KEY_ALG_INFO: 12,
        COMPOUND_PRIVATE_KEY: 13,
        COMPOUND_PUBLIC_KEY: 14,
        CTR_DRBG: 15,
        CURVE25519: 16,
        ECC: 17,
        ECC_ALG_INFO: 18,
        ECC_PRIVATE_KEY: 19,
        ECC_PUBLIC_KEY: 20,
        ED25519: 21,
        ENTROPY_ACCUMULATOR: 22,
        FAKE_RANDOM: 23,
        FALCON: 24,
        HASH_BASED_ALG_INFO: 25,
        HKDF: 26,
        HMAC: 27,
        HYBRID_KEY_ALG: 28,
        HYBRID_KEY_ALG_INFO: 29,
        HYBRID_PRIVATE_KEY: 30,
        HYBRID_PUBLIC_KEY: 31,
        KDF1: 32,
        KDF2: 33,
        KEY_ASN1_DESERIALIZER: 34,
        KEY_ASN1_SERIALIZER: 35,
        KEY_MATERIAL_RNG: 36,
        MESSAGE_INFO_DER_SERIALIZER: 37,
        ML_DSA: 38,
        ML_KEM: 39,
        PBE_ALG_INFO: 40,
        PKCS5_PBES2: 41,
        PKCS5_PBKDF2: 42,
        PKCS8_SERIALIZER: 43,
        RANDOM_PADDING: 44,
        RAW_PRIVATE_KEY: 45,
        RAW_PUBLIC_KEY: 46,
        RSA: 47,
        RSA_PRIVATE_KEY: 48,
        RSA_PUBLIC_KEY: 49,
        SALTED_KDF_ALG_INFO: 50,
        SEC1_SERIALIZER: 51,
        SEED_ENTROPY_SOURCE: 52,
        SHA224: 53,
        SHA256: 54,
        SHA384: 55,
        SHA512: 56,
        SIMPLE_ALG_INFO: 57,
    });

    return FoundationImplTag;
};

module.exports = initFoundationImplTag;
