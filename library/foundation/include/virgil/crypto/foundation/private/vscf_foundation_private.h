//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  This is an umbrella header that includes library private headers.
// --------------------------------------------------------------------------

#ifndef VSCF_FOUNDATION_PRIVATE_H_INCLUDED
#define VSCF_FOUNDATION_PRIVATE_H_INCLUDED

#include "vscf_platform.h"
#include "vscf_api_private.h"
#include "vscf_atomic.h"
#include "vscf_base64_private.h"
#include "vscf_impl_private.h"
#include "vscf_mbedtls_bridge_entropy.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_recipient_cipher_decryption_state.h"

#if VSCF_AES256_CBC
#   include "vscf_aes256_cbc_defs.h"
#endif

#if VSCF_AES256_GCM
#   include "vscf_aes256_gcm_defs.h"
#endif

#if VSCF_ALG
#   include "vscf_alg_api.h"
#endif

#if VSCF_ALG_INFO
#   include "vscf_alg_info_api.h"
#endif

#if VSCF_ALG_INFO_DER_DESERIALIZER
#   include "vscf_alg_info_der_deserializer_defs.h"
#endif

#if VSCF_ALG_INFO_DER_SERIALIZER
#   include "vscf_alg_info_der_serializer_defs.h"
#endif

#if VSCF_ALG_INFO_DESERIALIZER
#   include "vscf_alg_info_deserializer_api.h"
#endif

#if VSCF_ALG_INFO_SERIALIZER
#   include "vscf_alg_info_serializer_api.h"
#endif

#if VSCF_ASN1RD
#   include "vscf_asn1rd_defs.h"
#endif

#if VSCF_ASN1WR
#   include "vscf_asn1wr_defs.h"
#endif

#if VSCF_ASN1_READER
#   include "vscf_asn1_reader_api.h"
#endif

#if VSCF_ASN1_WRITER
#   include "vscf_asn1_writer_api.h"
#endif

#if VSCF_AUTH_DECRYPT
#   include "vscf_auth_decrypt_api.h"
#endif

#if VSCF_AUTH_ENCRYPT
#   include "vscf_auth_encrypt_api.h"
#endif

#if VSCF_CIPHER
#   include "vscf_cipher_api.h"
#endif

#if VSCF_CIPHER_ALG_INFO
#   include "vscf_cipher_alg_info_defs.h"
#endif

#if VSCF_CIPHER_AUTH
#   include "vscf_cipher_auth_api.h"
#endif

#if VSCF_CIPHER_AUTH_INFO
#   include "vscf_cipher_auth_info_api.h"
#endif

#if VSCF_CIPHER_INFO
#   include "vscf_cipher_info_api.h"
#endif

#if VSCF_COMPOUND_KEY_ALG
#   include "vscf_compound_key_alg_defs.h"
#endif

#if VSCF_COMPOUND_KEY_ALG_INFO
#   include "vscf_compound_key_alg_info_defs.h"
#endif

#if VSCF_COMPOUND_PRIVATE_KEY
#   include "vscf_compound_private_key_defs.h"
#endif

#if VSCF_COMPOUND_PUBLIC_KEY
#   include "vscf_compound_public_key_defs.h"
#endif

#if VSCF_COMPUTE_SHARED_KEY
#   include "vscf_compute_shared_key_api.h"
#endif

#if VSCF_CTR_DRBG
#   include "vscf_ctr_drbg_defs.h"
#endif

#if VSCF_CURVE25519
#   include "vscf_curve25519_defs.h"
#endif

#if VSCF_DECRYPT
#   include "vscf_decrypt_api.h"
#endif

#if VSCF_ECC
#   include "vscf_ecc_defs.h"
#endif

#if VSCF_ECC_ALG_INFO
#   include "vscf_ecc_alg_info_defs.h"
#endif

#if VSCF_ECC_PRIVATE_KEY
#   include "vscf_ecc_private_key_defs.h"
#endif

#if VSCF_ECC_PUBLIC_KEY
#   include "vscf_ecc_public_key_defs.h"
#endif

#if VSCF_ECIES
#   include "vscf_ecies_defs.h"
#endif

#if VSCF_ED25519
#   include "vscf_ed25519_defs.h"
#endif

#if VSCF_ENCRYPT
#   include "vscf_encrypt_api.h"
#endif

#if VSCF_ENTROPY_ACCUMULATOR
#   include "vscf_entropy_accumulator_defs.h"
#endif

#if VSCF_ENTROPY_SOURCE
#   include "vscf_entropy_source_api.h"
#endif

#if VSCF_FAKE_RANDOM
#   include "vscf_fake_random_defs.h"
#endif

#if VSCF_FALCON
#   include "vscf_falcon_defs.h"
#endif

#if VSCF_FOOTER_INFO
#   include "vscf_footer_info_defs.h"
#endif

#if VSCF_GROUP_SESSION_MESSAGE
#   include "vscf_group_session_message_defs.h"
#endif

#if VSCF_GROUP_SESSION_TICKET
#   include "vscf_group_session_ticket_defs.h"
#endif

#if VSCF_HASH
#   include "vscf_hash_api.h"
#endif

#if VSCF_HASH_BASED_ALG_INFO
#   include "vscf_hash_based_alg_info_defs.h"
#endif

#if VSCF_HKDF
#   include "vscf_hkdf_defs.h"
#   include "vscf_hkdf_private.h"
#endif

#if VSCF_HMAC
#   include "vscf_hmac_defs.h"
#endif

#if VSCF_HYBRID_KEY_ALG
#   include "vscf_hybrid_key_alg_defs.h"
#endif

#if VSCF_HYBRID_KEY_ALG_INFO
#   include "vscf_hybrid_key_alg_info_defs.h"
#endif

#if VSCF_HYBRID_PRIVATE_KEY
#   include "vscf_hybrid_private_key_defs.h"
#endif

#if VSCF_HYBRID_PUBLIC_KEY
#   include "vscf_hybrid_public_key_defs.h"
#endif

#if VSCF_KDF
#   include "vscf_kdf_api.h"
#endif

#if VSCF_KDF1
#   include "vscf_kdf1_defs.h"
#endif

#if VSCF_KDF2
#   include "vscf_kdf2_defs.h"
#endif

#if VSCF_KEM
#   include "vscf_kem_api.h"
#endif

#if VSCF_KEY
#   include "vscf_key_api.h"
#endif

#if VSCF_KEY_ALG
#   include "vscf_key_alg_api.h"
#endif

#if VSCF_KEY_ASN1_DESERIALIZER
#   include "vscf_key_asn1_deserializer_defs.h"
#endif

#if VSCF_KEY_ASN1_SERIALIZER
#   include "vscf_key_asn1_serializer_defs.h"
#endif

#if VSCF_KEY_CIPHER
#   include "vscf_key_cipher_api.h"
#endif

#if VSCF_KEY_DESERIALIZER
#   include "vscf_key_deserializer_api.h"
#endif

#if VSCF_KEY_INFO
#   include "vscf_key_info_defs.h"
#endif

#if VSCF_KEY_MATERIAL_RNG
#   include "vscf_key_material_rng_defs.h"
#endif

#if VSCF_KEY_PROVIDER
#   include "vscf_key_provider_defs.h"
#endif

#if VSCF_KEY_RECIPIENT_INFO
#   include "vscf_key_recipient_info_defs.h"
#endif

#if VSCF_KEY_RECIPIENT_INFO_LIST
#   include "vscf_key_recipient_info_list_defs.h"
#endif

#if VSCF_KEY_SERIALIZER
#   include "vscf_key_serializer_api.h"
#endif

#if VSCF_KEY_SIGNER
#   include "vscf_key_signer_api.h"
#endif

#if VSCF_MAC
#   include "vscf_mac_api.h"
#endif

#if VSCF_MESSAGE_CIPHER
#   include "vscf_message_cipher.h"
#endif

#if VSCF_MESSAGE_INFO
#   include "vscf_message_info_defs.h"
#endif

#if VSCF_MESSAGE_INFO_CUSTOM_PARAMS
#   include "vscf_message_info_custom_params_defs.h"
#endif

#if VSCF_MESSAGE_INFO_DER_SERIALIZER
#   include "vscf_message_info_der_serializer_defs.h"
#endif

#if VSCF_MESSAGE_INFO_EDITOR
#   include "vscf_message_info_editor_defs.h"
#endif

#if VSCF_MESSAGE_INFO_FOOTER
#   include "vscf_message_info_footer_defs.h"
#endif

#if VSCF_MESSAGE_INFO_FOOTER_SERIALIZER
#   include "vscf_message_info_footer_serializer_api.h"
#endif

#if VSCF_MESSAGE_INFO_SERIALIZER
#   include "vscf_message_info_serializer_api.h"
#endif

#if VSCF_MESSAGE_PADDING
#   include "vscf_message_padding.h"
#endif

#if VSCF_PADDING
#   include "vscf_padding_api.h"
#endif

#if VSCF_PADDING_PARAMS
#   include "vscf_padding_params_defs.h"
#endif

#if VSCF_PASSWORD_RECIPIENT_INFO
#   include "vscf_password_recipient_info_defs.h"
#endif

#if VSCF_PASSWORD_RECIPIENT_INFO_LIST
#   include "vscf_password_recipient_info_list_defs.h"
#endif

#if VSCF_PBE_ALG_INFO
#   include "vscf_pbe_alg_info_defs.h"
#endif

#if VSCF_PKCS5_PBES2
#   include "vscf_pkcs5_pbes2_defs.h"
#endif

#if VSCF_PKCS5_PBKDF2
#   include "vscf_pkcs5_pbkdf2_defs.h"
#endif

#if VSCF_PKCS8_SERIALIZER
#   include "vscf_pkcs8_serializer_defs.h"
#endif

#if VSCF_PRIVATE_KEY
#   include "vscf_private_key_api.h"
#endif

#if VSCF_PUBLIC_KEY
#   include "vscf_public_key_api.h"
#endif

#if VSCF_RANDOM
#   include "vscf_random_api.h"
#endif

#if VSCF_RANDOM_PADDING
#   include "vscf_random_padding_defs.h"
#endif

#if VSCF_RAW_PRIVATE_KEY
#   include "vscf_raw_private_key_defs.h"
#endif

#if VSCF_RAW_PUBLIC_KEY
#   include "vscf_raw_public_key_defs.h"
#endif

#if VSCF_RECIPIENT_CIPHER
#   include "vscf_recipient_cipher_defs.h"
#endif

#if VSCF_ROUND5
#   include "vscf_round5_defs.h"
#endif

#if VSCF_RSA
#   include "vscf_rsa_defs.h"
#endif

#if VSCF_RSA_PRIVATE_KEY
#   include "vscf_rsa_private_key_defs.h"
#endif

#if VSCF_RSA_PUBLIC_KEY
#   include "vscf_rsa_public_key_defs.h"
#endif

#if VSCF_SALTED_KDF
#   include "vscf_salted_kdf_api.h"
#endif

#if VSCF_SALTED_KDF_ALG_INFO
#   include "vscf_salted_kdf_alg_info_defs.h"
#endif

#if VSCF_SEC1_SERIALIZER
#   include "vscf_sec1_serializer_defs.h"
#endif

#if VSCF_SEED_ENTROPY_SOURCE
#   include "vscf_seed_entropy_source_defs.h"
#endif

#if VSCF_SHA224
#   include "vscf_sha224_defs.h"
#endif

#if VSCF_SHA256
#   include "vscf_sha256_defs.h"
#endif

#if VSCF_SHA384
#   include "vscf_sha384_defs.h"
#endif

#if VSCF_SHA512
#   include "vscf_sha512_defs.h"
#endif

#if VSCF_SIGNED_DATA_INFO
#   include "vscf_signed_data_info_defs.h"
#endif

#if VSCF_SIGNER
#   include "vscf_signer_defs.h"
#endif

#if VSCF_SIGNER_INFO
#   include "vscf_signer_info_defs.h"
#endif

#if VSCF_SIGNER_INFO_LIST
#   include "vscf_signer_info_list_defs.h"
#endif

#if VSCF_SIMPLE_ALG_INFO
#   include "vscf_simple_alg_info_defs.h"
#endif

#if VSCF_SIMPLE_SWU
#   include "vscf_simple_swu.h"
#endif

#if VSCF_VERIFIER
#   include "vscf_verifier_defs.h"
#endif

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


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_FOUNDATION_PRIVATE_H_INCLUDED
//  @end
