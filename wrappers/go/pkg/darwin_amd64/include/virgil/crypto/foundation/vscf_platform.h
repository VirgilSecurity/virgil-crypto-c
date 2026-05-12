//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This file contains platform specific information that is known during compilation.
// --------------------------------------------------------------------------

#ifndef VSCF_PLATFORM_H_INCLUDED
#define VSCF_PLATFORM_H_INCLUDED

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

#ifndef VSCF_HAVE_ASSERT_H
#define VSCF_HAVE_ASSERT_H 1
#endif

#ifndef VSCF_HAVE_STDATOMIC_H
#define VSCF_HAVE_STDATOMIC_H 1
#endif

#ifndef VSCF_SHARED_LIBRARY
#define VSCF_SHARED_LIBRARY 0
#endif

#ifndef VSCF_MULTI_THREADING
#define VSCF_MULTI_THREADING 1
#endif

#ifndef VSCF_POST_QUANTUM
#define VSCF_POST_QUANTUM 1
#endif

#ifndef VSCF_CIPHER
#define VSCF_CIPHER 1
#endif

#ifndef VSCF_AUTH_ENCRYPT
#define VSCF_AUTH_ENCRYPT 1
#endif

#ifndef VSCF_AUTH_DECRYPT
#define VSCF_AUTH_DECRYPT 1
#endif

#ifndef VSCF_CIPHER_AUTH
#define VSCF_CIPHER_AUTH 1
#endif

#ifndef VSCF_CIPHER_AUTH_INFO
#define VSCF_CIPHER_AUTH_INFO 1
#endif

#ifndef VSCF_CIPHER_INFO
#define VSCF_CIPHER_INFO 1
#endif

#ifndef VSCF_DECRYPT
#define VSCF_DECRYPT 1
#endif

#ifndef VSCF_ENCRYPT
#define VSCF_ENCRYPT 1
#endif

#ifndef VSCF_SALTED_KDF
#define VSCF_SALTED_KDF 1
#endif

#ifndef VSCF_HASH
#define VSCF_HASH 1
#endif

#ifndef VSCF_MAC
#define VSCF_MAC 1
#endif

#ifndef VSCF_KDF
#define VSCF_KDF 1
#endif

#ifndef VSCF_RANDOM
#define VSCF_RANDOM 1
#endif

#ifndef VSCF_ENTROPY_SOURCE
#define VSCF_ENTROPY_SOURCE 1
#endif

#ifndef VSCF_KEY
#define VSCF_KEY 1
#endif

#ifndef VSCF_KEY_ALG
#define VSCF_KEY_ALG 1
#endif

#ifndef VSCF_PUBLIC_KEY
#define VSCF_PUBLIC_KEY 1
#endif

#ifndef VSCF_PRIVATE_KEY
#define VSCF_PRIVATE_KEY 1
#endif

#ifndef VSCF_KEY_CIPHER
#define VSCF_KEY_CIPHER 1
#endif

#ifndef VSCF_KEY_SIGNER
#define VSCF_KEY_SIGNER 1
#endif

#ifndef VSCF_COMPUTE_SHARED_KEY
#define VSCF_COMPUTE_SHARED_KEY 1
#endif

#ifndef VSCF_KEY_SERIALIZER
#define VSCF_KEY_SERIALIZER 1
#endif

#ifndef VSCF_KEY_DESERIALIZER
#define VSCF_KEY_DESERIALIZER 1
#endif

#ifndef VSCF_ASN1_READER
#define VSCF_ASN1_READER 1
#endif

#ifndef VSCF_ASN1_WRITER
#define VSCF_ASN1_WRITER 1
#endif

#ifndef VSCF_ALG
#define VSCF_ALG 1
#endif

#ifndef VSCF_ALG_INFO
#define VSCF_ALG_INFO 1
#endif

#ifndef VSCF_ALG_INFO_SERIALIZER
#define VSCF_ALG_INFO_SERIALIZER 1
#endif

#ifndef VSCF_ALG_INFO_DESERIALIZER
#define VSCF_ALG_INFO_DESERIALIZER 1
#endif

#ifndef VSCF_MESSAGE_INFO_SERIALIZER
#define VSCF_MESSAGE_INFO_SERIALIZER 1
#endif

#ifndef VSCF_MESSAGE_INFO_FOOTER_SERIALIZER
#define VSCF_MESSAGE_INFO_FOOTER_SERIALIZER 1
#endif

#ifndef VSCF_PADDING
#define VSCF_PADDING 1
#endif

#ifndef VSCF_KEM
#define VSCF_KEM 1
#endif

#ifndef VSCF_SHA224
#define VSCF_SHA224 1
#endif

#ifndef VSCF_SHA256
#define VSCF_SHA256 1
#endif

#ifndef VSCF_SHA384
#define VSCF_SHA384 1
#endif

#ifndef VSCF_SHA512
#define VSCF_SHA512 1
#endif

#ifndef VSCF_AES256_GCM
#define VSCF_AES256_GCM 1
#endif

#ifndef VSCF_AES256_CBC
#define VSCF_AES256_CBC 1
#endif

#ifndef VSCF_ASN1RD
#define VSCF_ASN1RD 1
#endif

#ifndef VSCF_ASN1WR
#define VSCF_ASN1WR 1
#endif

#ifndef VSCF_RSA_PUBLIC_KEY
#define VSCF_RSA_PUBLIC_KEY 1
#endif

#ifndef VSCF_RSA_PRIVATE_KEY
#define VSCF_RSA_PRIVATE_KEY 1
#endif

#ifndef VSCF_RSA
#define VSCF_RSA 1
#endif

#ifndef VSCF_ECC_PUBLIC_KEY
#define VSCF_ECC_PUBLIC_KEY 1
#endif

#ifndef VSCF_ECC_PRIVATE_KEY
#define VSCF_ECC_PRIVATE_KEY 1
#endif

#ifndef VSCF_ECC
#define VSCF_ECC 1
#endif

#ifndef VSCF_ENTROPY_ACCUMULATOR
#define VSCF_ENTROPY_ACCUMULATOR 1
#endif

#ifndef VSCF_CTR_DRBG
#define VSCF_CTR_DRBG 1
#endif

#ifndef VSCF_HMAC
#define VSCF_HMAC 1
#endif

#ifndef VSCF_HKDF
#define VSCF_HKDF 1
#endif

#ifndef VSCF_KDF1
#define VSCF_KDF1 1
#endif

#ifndef VSCF_KDF2
#define VSCF_KDF2 1
#endif

#ifndef VSCF_FAKE_RANDOM
#define VSCF_FAKE_RANDOM 1
#endif

#ifndef VSCF_PKCS5_PBKDF2
#define VSCF_PKCS5_PBKDF2 1
#endif

#ifndef VSCF_PKCS5_PBES2
#define VSCF_PKCS5_PBES2 1
#endif

#ifndef VSCF_SEED_ENTROPY_SOURCE
#define VSCF_SEED_ENTROPY_SOURCE 1
#endif

#ifndef VSCF_KEY_MATERIAL_RNG
#define VSCF_KEY_MATERIAL_RNG 1
#endif

#ifndef VSCF_RAW_PUBLIC_KEY
#define VSCF_RAW_PUBLIC_KEY 1
#endif

#ifndef VSCF_RAW_PRIVATE_KEY
#define VSCF_RAW_PRIVATE_KEY 1
#endif

#ifndef VSCF_PKCS8_SERIALIZER
#define VSCF_PKCS8_SERIALIZER 1
#endif

#ifndef VSCF_SEC1_SERIALIZER
#define VSCF_SEC1_SERIALIZER 1
#endif

#ifndef VSCF_KEY_ASN1_SERIALIZER
#define VSCF_KEY_ASN1_SERIALIZER 1
#endif

#ifndef VSCF_KEY_ASN1_DESERIALIZER
#define VSCF_KEY_ASN1_DESERIALIZER 1
#endif

#ifndef VSCF_ED25519
#define VSCF_ED25519 1
#endif

#ifndef VSCF_CURVE25519
#define VSCF_CURVE25519 1
#endif

#ifndef VSCF_FALCON
#define VSCF_FALCON 1
#endif

#ifndef VSCF_COMPOUND_KEY_ALG_INFO
#define VSCF_COMPOUND_KEY_ALG_INFO 1
#endif

#ifndef VSCF_COMPOUND_PUBLIC_KEY
#define VSCF_COMPOUND_PUBLIC_KEY 1
#endif

#ifndef VSCF_COMPOUND_PRIVATE_KEY
#define VSCF_COMPOUND_PRIVATE_KEY 1
#endif

#ifndef VSCF_COMPOUND_KEY_ALG
#define VSCF_COMPOUND_KEY_ALG 1
#endif

#ifndef VSCF_HYBRID_KEY_ALG_INFO
#define VSCF_HYBRID_KEY_ALG_INFO 1
#endif

#ifndef VSCF_HYBRID_PUBLIC_KEY
#define VSCF_HYBRID_PUBLIC_KEY 1
#endif

#ifndef VSCF_HYBRID_PRIVATE_KEY
#define VSCF_HYBRID_PRIVATE_KEY 1
#endif

#ifndef VSCF_HYBRID_KEY_ALG
#define VSCF_HYBRID_KEY_ALG 1
#endif

#ifndef VSCF_SIMPLE_ALG_INFO
#define VSCF_SIMPLE_ALG_INFO 1
#endif

#ifndef VSCF_HASH_BASED_ALG_INFO
#define VSCF_HASH_BASED_ALG_INFO 1
#endif

#ifndef VSCF_CIPHER_ALG_INFO
#define VSCF_CIPHER_ALG_INFO 1
#endif

#ifndef VSCF_SALTED_KDF_ALG_INFO
#define VSCF_SALTED_KDF_ALG_INFO 1
#endif

#ifndef VSCF_PBE_ALG_INFO
#define VSCF_PBE_ALG_INFO 1
#endif

#ifndef VSCF_ECC_ALG_INFO
#define VSCF_ECC_ALG_INFO 1
#endif

#ifndef VSCF_ALG_INFO_DER_SERIALIZER
#define VSCF_ALG_INFO_DER_SERIALIZER 1
#endif

#ifndef VSCF_ALG_INFO_DER_DESERIALIZER
#define VSCF_ALG_INFO_DER_DESERIALIZER 1
#endif

#ifndef VSCF_MESSAGE_INFO_DER_SERIALIZER
#define VSCF_MESSAGE_INFO_DER_SERIALIZER 1
#endif

#ifndef VSCF_RANDOM_PADDING
#define VSCF_RANDOM_PADDING 1
#endif

#ifndef VSCF_ERROR
#define VSCF_ERROR 1
#endif

#ifndef VSCF_MBEDTLS_BIGNUM_ASN1_WRITER
#define VSCF_MBEDTLS_BIGNUM_ASN1_WRITER 1
#endif

#ifndef VSCF_MBEDTLS_BIGNUM_ASN1_READER
#define VSCF_MBEDTLS_BIGNUM_ASN1_READER 1
#endif

#ifndef VSCF_MBEDTLS_MD
#define VSCF_MBEDTLS_MD 1
#endif

#ifndef VSCF_MBEDTLS_ECP
#define VSCF_MBEDTLS_ECP 1
#endif

#ifndef VSCF_OID
#define VSCF_OID 1
#endif

#ifndef VSCF_BASE64
#define VSCF_BASE64 1
#endif

#ifndef VSCF_PEM
#define VSCF_PEM 1
#endif

#ifndef VSCF_PEM_TITLE
#define VSCF_PEM_TITLE 1
#endif

#ifndef VSCF_MESSAGE_INFO
#define VSCF_MESSAGE_INFO 1
#endif

#ifndef VSCF_KEY_RECIPIENT_INFO
#define VSCF_KEY_RECIPIENT_INFO 1
#endif

#ifndef VSCF_KEY_RECIPIENT_INFO_LIST
#define VSCF_KEY_RECIPIENT_INFO_LIST 1
#endif

#ifndef VSCF_PASSWORD_RECIPIENT_INFO
#define VSCF_PASSWORD_RECIPIENT_INFO 1
#endif

#ifndef VSCF_PASSWORD_RECIPIENT_INFO_LIST
#define VSCF_PASSWORD_RECIPIENT_INFO_LIST 1
#endif

#ifndef VSCF_ALG_FACTORY
#define VSCF_ALG_FACTORY 1
#endif

#ifndef VSCF_KEY_ALG_FACTORY
#define VSCF_KEY_ALG_FACTORY 1
#endif

#ifndef VSCF_ECIES
#define VSCF_ECIES 1
#endif

#ifndef VSCF_ECIES_ENVELOPE
#define VSCF_ECIES_ENVELOPE 1
#endif

#ifndef VSCF_RECIPIENT_CIPHER
#define VSCF_RECIPIENT_CIPHER 1
#endif

#ifndef VSCF_KEY_RECIPIENT_LIST
#define VSCF_KEY_RECIPIENT_LIST 1
#endif

#ifndef VSCF_LIST_KEY_VALUE_NODE
#define VSCF_LIST_KEY_VALUE_NODE 1
#endif

#ifndef VSCF_MESSAGE_INFO_CUSTOM_PARAMS
#define VSCF_MESSAGE_INFO_CUSTOM_PARAMS 1
#endif

#ifndef VSCF_KEY_PROVIDER
#define VSCF_KEY_PROVIDER 1
#endif

#ifndef VSCF_SIGNER
#define VSCF_SIGNER 1
#endif

#ifndef VSCF_VERIFIER
#define VSCF_VERIFIER 1
#endif

#ifndef VSCF_SIMPLE_SWU
#define VSCF_SIMPLE_SWU 1
#endif

#ifndef VSCF_BRAINKEY_CLIENT
#define VSCF_BRAINKEY_CLIENT 1
#endif

#ifndef VSCF_BRAINKEY_SERVER
#define VSCF_BRAINKEY_SERVER 1
#endif

#ifndef VSCF_MESSAGE_PADDING
#define VSCF_MESSAGE_PADDING 1
#endif

#ifndef VSCF_MESSAGE_CIPHER
#define VSCF_MESSAGE_CIPHER 1
#endif

#ifndef VSCF_GROUP_SESSION_MESSAGE
#define VSCF_GROUP_SESSION_MESSAGE 1
#endif

#ifndef VSCF_GROUP_SESSION_TICKET
#define VSCF_GROUP_SESSION_TICKET 1
#endif

#ifndef VSCF_GROUP_SESSION
#define VSCF_GROUP_SESSION 1
#endif

#ifndef VSCF_GROUP_SESSION_EPOCH
#define VSCF_GROUP_SESSION_EPOCH 1
#endif

#ifndef VSCF_GROUP_SESSION_EPOCH_NODE
#define VSCF_GROUP_SESSION_EPOCH_NODE 1
#endif

#ifndef VSCF_MESSAGE_INFO_EDITOR
#define VSCF_MESSAGE_INFO_EDITOR 1
#endif

#ifndef VSCF_SIGNER_INFO
#define VSCF_SIGNER_INFO 1
#endif

#ifndef VSCF_SIGNER_INFO_LIST
#define VSCF_SIGNER_INFO_LIST 1
#endif

#ifndef VSCF_SIGNER_LIST
#define VSCF_SIGNER_LIST 1
#endif

#ifndef VSCF_MESSAGE_INFO_FOOTER
#define VSCF_MESSAGE_INFO_FOOTER 1
#endif

#ifndef VSCF_SIGNED_DATA_INFO
#define VSCF_SIGNED_DATA_INFO 1
#endif

#ifndef VSCF_FOOTER_INFO
#define VSCF_FOOTER_INFO 1
#endif

#ifndef VSCF_KEY_INFO
#define VSCF_KEY_INFO 1
#endif

#ifndef VSCF_TAIL_FILTER
#define VSCF_TAIL_FILTER 1
#endif

#ifndef VSCF_PADDING_PARAMS
#define VSCF_PADDING_PARAMS 1
#endif

#ifndef VSCF_PADDING_CIPHER
#define VSCF_PADDING_CIPHER 1
#endif

//
//  Defines namespace include prefix for project 'common'.
//
#if !defined(VSCF_INTERNAL_BUILD)
#define VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#else
#define VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#endif


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PLATFORM_H_INCLUDED
//  @end
