#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2019 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

if(NOT TARGET foundation)
    message(FATAL_ERROR "Expected target 'foundation' to be defined first.")
endif()

target_compile_definitions(foundation
        PUBLIC
            $<BUILD_INTERFACE:VSCF_INTERNAL_BUILD>
            "VSCF_SHARED_LIBRARY=$<BOOL:${BUILD_SHARED_LIBS}>"
            "VSCF_LIBRARY=$<BOOL:${VSCF_LIBRARY}>"
            "VSCF_MULTI_THREADING=$<BOOL:${VSCF_MULTI_THREADING}>"
            "VSCF_POST_QUANTUM=$<BOOL:${VSCF_POST_QUANTUM}>"
            "VSCF_CIPHER=$<BOOL:${VSCF_CIPHER}>"
            "VSCF_AUTH_ENCRYPT=$<BOOL:${VSCF_AUTH_ENCRYPT}>"
            "VSCF_AUTH_DECRYPT=$<BOOL:${VSCF_AUTH_DECRYPT}>"
            "VSCF_CIPHER_AUTH=$<BOOL:${VSCF_CIPHER_AUTH}>"
            "VSCF_CIPHER_AUTH_INFO=$<BOOL:${VSCF_CIPHER_AUTH_INFO}>"
            "VSCF_CIPHER_INFO=$<BOOL:${VSCF_CIPHER_INFO}>"
            "VSCF_DECRYPT=$<BOOL:${VSCF_DECRYPT}>"
            "VSCF_ENCRYPT=$<BOOL:${VSCF_ENCRYPT}>"
            "VSCF_SALTED_KDF=$<BOOL:${VSCF_SALTED_KDF}>"
            "VSCF_HASH=$<BOOL:${VSCF_HASH}>"
            "VSCF_MAC=$<BOOL:${VSCF_MAC}>"
            "VSCF_KDF=$<BOOL:${VSCF_KDF}>"
            "VSCF_RANDOM=$<BOOL:${VSCF_RANDOM}>"
            "VSCF_ENTROPY_SOURCE=$<BOOL:${VSCF_ENTROPY_SOURCE}>"
            "VSCF_KEY=$<BOOL:${VSCF_KEY}>"
            "VSCF_KEY_ALG=$<BOOL:${VSCF_KEY_ALG}>"
            "VSCF_PUBLIC_KEY=$<BOOL:${VSCF_PUBLIC_KEY}>"
            "VSCF_PRIVATE_KEY=$<BOOL:${VSCF_PRIVATE_KEY}>"
            "VSCF_KEY_CIPHER=$<BOOL:${VSCF_KEY_CIPHER}>"
            "VSCF_KEY_SIGNER=$<BOOL:${VSCF_KEY_SIGNER}>"
            "VSCF_COMPUTE_SHARED_KEY=$<BOOL:${VSCF_COMPUTE_SHARED_KEY}>"
            "VSCF_KEY_SERIALIZER=$<BOOL:${VSCF_KEY_SERIALIZER}>"
            "VSCF_KEY_DESERIALIZER=$<BOOL:${VSCF_KEY_DESERIALIZER}>"
            "VSCF_ASN1_READER=$<BOOL:${VSCF_ASN1_READER}>"
            "VSCF_ASN1_WRITER=$<BOOL:${VSCF_ASN1_WRITER}>"
            "VSCF_ALG=$<BOOL:${VSCF_ALG}>"
            "VSCF_ALG_INFO=$<BOOL:${VSCF_ALG_INFO}>"
            "VSCF_ALG_INFO_SERIALIZER=$<BOOL:${VSCF_ALG_INFO_SERIALIZER}>"
            "VSCF_ALG_INFO_DESERIALIZER=$<BOOL:${VSCF_ALG_INFO_DESERIALIZER}>"
            "VSCF_MESSAGE_INFO_SERIALIZER=$<BOOL:${VSCF_MESSAGE_INFO_SERIALIZER}>"
            "VSCF_MESSAGE_INFO_FOOTER_SERIALIZER=$<BOOL:${VSCF_MESSAGE_INFO_FOOTER_SERIALIZER}>"
            "VSCF_PADDING=$<BOOL:${VSCF_PADDING}>"
            "VSCF_KEM=$<BOOL:${VSCF_KEM}>"
            "VSCF_SHA224=$<BOOL:${VSCF_SHA224}>"
            "VSCF_SHA256=$<BOOL:${VSCF_SHA256}>"
            "VSCF_SHA384=$<BOOL:${VSCF_SHA384}>"
            "VSCF_SHA512=$<BOOL:${VSCF_SHA512}>"
            "VSCF_AES256_GCM=$<BOOL:${VSCF_AES256_GCM}>"
            "VSCF_AES256_CBC=$<BOOL:${VSCF_AES256_CBC}>"
            "VSCF_ASN1RD=$<BOOL:${VSCF_ASN1RD}>"
            "VSCF_ASN1WR=$<BOOL:${VSCF_ASN1WR}>"
            "VSCF_RSA_PUBLIC_KEY=$<BOOL:${VSCF_RSA_PUBLIC_KEY}>"
            "VSCF_RSA_PRIVATE_KEY=$<BOOL:${VSCF_RSA_PRIVATE_KEY}>"
            "VSCF_RSA=$<BOOL:${VSCF_RSA}>"
            "VSCF_ECC_PUBLIC_KEY=$<BOOL:${VSCF_ECC_PUBLIC_KEY}>"
            "VSCF_ECC_PRIVATE_KEY=$<BOOL:${VSCF_ECC_PRIVATE_KEY}>"
            "VSCF_ECC=$<BOOL:${VSCF_ECC}>"
            "VSCF_ENTROPY_ACCUMULATOR=$<BOOL:${VSCF_ENTROPY_ACCUMULATOR}>"
            "VSCF_CTR_DRBG=$<BOOL:${VSCF_CTR_DRBG}>"
            "VSCF_HMAC=$<BOOL:${VSCF_HMAC}>"
            "VSCF_HKDF=$<BOOL:${VSCF_HKDF}>"
            "VSCF_KDF1=$<BOOL:${VSCF_KDF1}>"
            "VSCF_KDF2=$<BOOL:${VSCF_KDF2}>"
            "VSCF_FAKE_RANDOM=$<BOOL:${VSCF_FAKE_RANDOM}>"
            "VSCF_PKCS5_PBKDF2=$<BOOL:${VSCF_PKCS5_PBKDF2}>"
            "VSCF_PKCS5_PBES2=$<BOOL:${VSCF_PKCS5_PBES2}>"
            "VSCF_SEED_ENTROPY_SOURCE=$<BOOL:${VSCF_SEED_ENTROPY_SOURCE}>"
            "VSCF_KEY_MATERIAL_RNG=$<BOOL:${VSCF_KEY_MATERIAL_RNG}>"
            "VSCF_RAW_PUBLIC_KEY=$<BOOL:${VSCF_RAW_PUBLIC_KEY}>"
            "VSCF_RAW_PRIVATE_KEY=$<BOOL:${VSCF_RAW_PRIVATE_KEY}>"
            "VSCF_PKCS8_SERIALIZER=$<BOOL:${VSCF_PKCS8_SERIALIZER}>"
            "VSCF_SEC1_SERIALIZER=$<BOOL:${VSCF_SEC1_SERIALIZER}>"
            "VSCF_KEY_ASN1_SERIALIZER=$<BOOL:${VSCF_KEY_ASN1_SERIALIZER}>"
            "VSCF_KEY_ASN1_DESERIALIZER=$<BOOL:${VSCF_KEY_ASN1_DESERIALIZER}>"
            "VSCF_ED25519=$<BOOL:${VSCF_ED25519}>"
            "VSCF_CURVE25519=$<BOOL:${VSCF_CURVE25519}>"
            "VSCF_FALCON=$<BOOL:${VSCF_FALCON}>"
            "VSCF_ROUND5=$<BOOL:${VSCF_ROUND5}>"
            "VSCF_COMPOUND_KEY_ALG_INFO=$<BOOL:${VSCF_COMPOUND_KEY_ALG_INFO}>"
            "VSCF_COMPOUND_PUBLIC_KEY=$<BOOL:${VSCF_COMPOUND_PUBLIC_KEY}>"
            "VSCF_COMPOUND_PRIVATE_KEY=$<BOOL:${VSCF_COMPOUND_PRIVATE_KEY}>"
            "VSCF_COMPOUND_KEY_ALG=$<BOOL:${VSCF_COMPOUND_KEY_ALG}>"
            "VSCF_HYBRID_KEY_ALG_INFO=$<BOOL:${VSCF_HYBRID_KEY_ALG_INFO}>"
            "VSCF_HYBRID_PUBLIC_KEY=$<BOOL:${VSCF_HYBRID_PUBLIC_KEY}>"
            "VSCF_HYBRID_PRIVATE_KEY=$<BOOL:${VSCF_HYBRID_PRIVATE_KEY}>"
            "VSCF_HYBRID_KEY_ALG=$<BOOL:${VSCF_HYBRID_KEY_ALG}>"
            "VSCF_SIMPLE_ALG_INFO=$<BOOL:${VSCF_SIMPLE_ALG_INFO}>"
            "VSCF_HASH_BASED_ALG_INFO=$<BOOL:${VSCF_HASH_BASED_ALG_INFO}>"
            "VSCF_CIPHER_ALG_INFO=$<BOOL:${VSCF_CIPHER_ALG_INFO}>"
            "VSCF_SALTED_KDF_ALG_INFO=$<BOOL:${VSCF_SALTED_KDF_ALG_INFO}>"
            "VSCF_PBE_ALG_INFO=$<BOOL:${VSCF_PBE_ALG_INFO}>"
            "VSCF_ECC_ALG_INFO=$<BOOL:${VSCF_ECC_ALG_INFO}>"
            "VSCF_ALG_INFO_DER_SERIALIZER=$<BOOL:${VSCF_ALG_INFO_DER_SERIALIZER}>"
            "VSCF_ALG_INFO_DER_DESERIALIZER=$<BOOL:${VSCF_ALG_INFO_DER_DESERIALIZER}>"
            "VSCF_MESSAGE_INFO_DER_SERIALIZER=$<BOOL:${VSCF_MESSAGE_INFO_DER_SERIALIZER}>"
            "VSCF_RANDOM_PADDING=$<BOOL:${VSCF_RANDOM_PADDING}>"
            "VSCF_ERROR=$<BOOL:${VSCF_ERROR}>"
            "VSCF_MBEDTLS_BIGNUM_ASN1_WRITER=$<BOOL:${VSCF_MBEDTLS_BIGNUM_ASN1_WRITER}>"
            "VSCF_MBEDTLS_BIGNUM_ASN1_READER=$<BOOL:${VSCF_MBEDTLS_BIGNUM_ASN1_READER}>"
            "VSCF_MBEDTLS_MD=$<BOOL:${VSCF_MBEDTLS_MD}>"
            "VSCF_MBEDTLS_ECP=$<BOOL:${VSCF_MBEDTLS_ECP}>"
            "VSCF_OID=$<BOOL:${VSCF_OID}>"
            "VSCF_BASE64=$<BOOL:${VSCF_BASE64}>"
            "VSCF_PEM=$<BOOL:${VSCF_PEM}>"
            "VSCF_PEM_TITLE=$<BOOL:${VSCF_PEM_TITLE}>"
            "VSCF_MESSAGE_INFO=$<BOOL:${VSCF_MESSAGE_INFO}>"
            "VSCF_KEY_RECIPIENT_INFO=$<BOOL:${VSCF_KEY_RECIPIENT_INFO}>"
            "VSCF_KEY_RECIPIENT_INFO_LIST=$<BOOL:${VSCF_KEY_RECIPIENT_INFO_LIST}>"
            "VSCF_PASSWORD_RECIPIENT_INFO=$<BOOL:${VSCF_PASSWORD_RECIPIENT_INFO}>"
            "VSCF_PASSWORD_RECIPIENT_INFO_LIST=$<BOOL:${VSCF_PASSWORD_RECIPIENT_INFO_LIST}>"
            "VSCF_ALG_FACTORY=$<BOOL:${VSCF_ALG_FACTORY}>"
            "VSCF_KEY_ALG_FACTORY=$<BOOL:${VSCF_KEY_ALG_FACTORY}>"
            "VSCF_ECIES=$<BOOL:${VSCF_ECIES}>"
            "VSCF_ECIES_ENVELOPE=$<BOOL:${VSCF_ECIES_ENVELOPE}>"
            "VSCF_RECIPIENT_CIPHER=$<BOOL:${VSCF_RECIPIENT_CIPHER}>"
            "VSCF_KEY_RECIPIENT_LIST=$<BOOL:${VSCF_KEY_RECIPIENT_LIST}>"
            "VSCF_LIST_KEY_VALUE_NODE=$<BOOL:${VSCF_LIST_KEY_VALUE_NODE}>"
            "VSCF_MESSAGE_INFO_CUSTOM_PARAMS=$<BOOL:${VSCF_MESSAGE_INFO_CUSTOM_PARAMS}>"
            "VSCF_KEY_PROVIDER=$<BOOL:${VSCF_KEY_PROVIDER}>"
            "VSCF_SIGNER=$<BOOL:${VSCF_SIGNER}>"
            "VSCF_VERIFIER=$<BOOL:${VSCF_VERIFIER}>"
            "VSCF_SIMPLE_SWU=$<BOOL:${VSCF_SIMPLE_SWU}>"
            "VSCF_BRAINKEY_CLIENT=$<BOOL:${VSCF_BRAINKEY_CLIENT}>"
            "VSCF_BRAINKEY_SERVER=$<BOOL:${VSCF_BRAINKEY_SERVER}>"
            "VSCF_MESSAGE_PADDING=$<BOOL:${VSCF_MESSAGE_PADDING}>"
            "VSCF_MESSAGE_CIPHER=$<BOOL:${VSCF_MESSAGE_CIPHER}>"
            "VSCF_GROUP_SESSION_MESSAGE=$<BOOL:${VSCF_GROUP_SESSION_MESSAGE}>"
            "VSCF_GROUP_SESSION_TICKET=$<BOOL:${VSCF_GROUP_SESSION_TICKET}>"
            "VSCF_GROUP_SESSION=$<BOOL:${VSCF_GROUP_SESSION}>"
            "VSCF_GROUP_SESSION_EPOCH=$<BOOL:${VSCF_GROUP_SESSION_EPOCH}>"
            "VSCF_GROUP_SESSION_EPOCH_NODE=$<BOOL:${VSCF_GROUP_SESSION_EPOCH_NODE}>"
            "VSCF_MESSAGE_INFO_EDITOR=$<BOOL:${VSCF_MESSAGE_INFO_EDITOR}>"
            "VSCF_SIGNER_INFO=$<BOOL:${VSCF_SIGNER_INFO}>"
            "VSCF_SIGNER_INFO_LIST=$<BOOL:${VSCF_SIGNER_INFO_LIST}>"
            "VSCF_SIGNER_LIST=$<BOOL:${VSCF_SIGNER_LIST}>"
            "VSCF_MESSAGE_INFO_FOOTER=$<BOOL:${VSCF_MESSAGE_INFO_FOOTER}>"
            "VSCF_SIGNED_DATA_INFO=$<BOOL:${VSCF_SIGNED_DATA_INFO}>"
            "VSCF_FOOTER_INFO=$<BOOL:${VSCF_FOOTER_INFO}>"
            "VSCF_KEY_INFO=$<BOOL:${VSCF_KEY_INFO}>"
            "VSCF_TAIL_FILTER=$<BOOL:${VSCF_TAIL_FILTER}>"
            "VSCF_PADDING_PARAMS=$<BOOL:${VSCF_PADDING_PARAMS}>"
            "VSCF_PADDING_CIPHER=$<BOOL:${VSCF_PADDING_CIPHER}>"
        )
