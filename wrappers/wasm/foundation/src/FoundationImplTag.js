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
        CHUNK_CIPHER: 10,
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
        HYBRID_KEY_ALG: 29,
        HYBRID_KEY_ALG_INFO: 30,
        HYBRID_PRIVATE_KEY: 31,
        HYBRID_PUBLIC_KEY: 32,
        KDF1: 33,
        KDF2: 34,
        KEY_ASN1_DESERIALIZER: 35,
        KEY_ASN1_SERIALIZER: 36,
        KEY_MATERIAL_RNG: 37,
        MESSAGE_INFO_DER_SERIALIZER: 38,
        ML_DSA: 39,
        ML_KEM: 40,
        PBE_ALG_INFO: 41,
        PKCS5_PBES2: 42,
        PKCS5_PBKDF2: 43,
        PKCS8_SERIALIZER: 44,
        RANDOM_PADDING: 45,
        RAW_PRIVATE_KEY: 46,
        RAW_PUBLIC_KEY: 47,
        RSA: 48,
        RSA_PRIVATE_KEY: 49,
        RSA_PUBLIC_KEY: 50,
        SALTED_KDF_ALG_INFO: 51,
        SEC1_SERIALIZER: 52,
        SEED_ENTROPY_SOURCE: 53,
        SHA224: 54,
        SHA256: 55,
        SHA384: 56,
        SHA512: 57,
        SIMPLE_ALG_INFO: 58,
    });

    return FoundationImplTag;
};

module.exports = initFoundationImplTag;
