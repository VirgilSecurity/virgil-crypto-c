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
//  This ia an umbrella header that includes library public headers.
// --------------------------------------------------------------------------

#ifndef VSCF_FOUNDATION_PUBLIC_H_INCLUDED
#define VSCF_FOUNDATION_PUBLIC_H_INCLUDED

#include "vscf_platform.h"
#include "vscf_alg_id.h"
#include "vscf_api.h"
#include "vscf_asn1_tag.h"
#include "vscf_assert.h"
#include "vscf_cipher_state.h"
#include "vscf_group_msg_type.h"
#include "vscf_impl.h"
#include "vscf_library.h"
#include "vscf_memory.h"
#include "vscf_oid_id.h"
#include "vscf_status.h"

#if VSCF_AES256_CBC
#   include "vscf_aes256_cbc.h"
#endif

#if VSCF_AES256_GCM
#   include "vscf_aes256_gcm.h"
#endif

#if VSCF_ALG
#   include "vscf_alg.h"
#endif

#if VSCF_ALG_FACTORY
#   include "vscf_alg_factory.h"
#endif

#if VSCF_ALG_INFO
#   include "vscf_alg_info.h"
#endif

#if VSCF_ALG_INFO_DER_DESERIALIZER
#   include "vscf_alg_info_der_deserializer.h"
#endif

#if VSCF_ALG_INFO_DER_SERIALIZER
#   include "vscf_alg_info_der_serializer.h"
#endif

#if VSCF_ALG_INFO_DESERIALIZER
#   include "vscf_alg_info_deserializer.h"
#endif

#if VSCF_ALG_INFO_SERIALIZER
#   include "vscf_alg_info_serializer.h"
#endif

#if VSCF_ASN1RD
#   include "vscf_asn1rd.h"
#endif

#if VSCF_ASN1WR
#   include "vscf_asn1wr.h"
#endif

#if VSCF_ASN1_READER
#   include "vscf_asn1_reader.h"
#endif

#if VSCF_ASN1_WRITER
#   include "vscf_asn1_writer.h"
#endif

#if VSCF_AUTH_DECRYPT
#   include "vscf_auth_decrypt.h"
#endif

#if VSCF_AUTH_ENCRYPT
#   include "vscf_auth_encrypt.h"
#endif

#if VSCF_BASE64
#   include "vscf_base64.h"
#endif

#if VSCF_BINARY
#   include "vscf_binary.h"
#endif

#if VSCF_BRAINKEY_CLIENT
#   include "vscf_brainkey_client.h"
#endif

#if VSCF_BRAINKEY_SERVER
#   include "vscf_brainkey_server.h"
#endif

#if VSCF_CIPHER
#   include "vscf_cipher.h"
#endif

#if VSCF_CIPHER_ALG_INFO
#   include "vscf_cipher_alg_info.h"
#endif

#if VSCF_CIPHER_AUTH
#   include "vscf_cipher_auth.h"
#endif

#if VSCF_CIPHER_AUTH_INFO
#   include "vscf_cipher_auth_info.h"
#endif

#if VSCF_CIPHER_INFO
#   include "vscf_cipher_info.h"
#endif

#if VSCF_COMPOUND_KEY_ALG
#   include "vscf_compound_key_alg.h"
#endif

#if VSCF_COMPOUND_KEY_ALG_INFO
#   include "vscf_compound_key_alg_info.h"
#endif

#if VSCF_COMPOUND_PRIVATE_KEY
#   include "vscf_compound_private_key.h"
#endif

#if VSCF_COMPOUND_PUBLIC_KEY
#   include "vscf_compound_public_key.h"
#endif

#if VSCF_COMPUTE_SHARED_KEY
#   include "vscf_compute_shared_key.h"
#endif

#if VSCF_CTR_DRBG
#   include "vscf_ctr_drbg.h"
#endif

#if VSCF_CURVE25519
#   include "vscf_curve25519.h"
#endif

#if VSCF_DECRYPT
#   include "vscf_decrypt.h"
#endif

#if VSCF_ECC
#   include "vscf_ecc.h"
#endif

#if VSCF_ECC_ALG_INFO
#   include "vscf_ecc_alg_info.h"
#endif

#if VSCF_ECC_PRIVATE_KEY
#   include "vscf_ecc_private_key.h"
#endif

#if VSCF_ECC_PUBLIC_KEY
#   include "vscf_ecc_public_key.h"
#endif

#if VSCF_ECIES
#   include "vscf_ecies.h"
#endif

#if VSCF_ED25519
#   include "vscf_ed25519.h"
#endif

#if VSCF_ENCRYPT
#   include "vscf_encrypt.h"
#endif

#if VSCF_ENTROPY_ACCUMULATOR
#   include "vscf_entropy_accumulator.h"
#endif

#if VSCF_ENTROPY_SOURCE
#   include "vscf_entropy_source.h"
#endif

#if VSCF_ERROR
#   include "vscf_error.h"
#endif

#if VSCF_FAKE_RANDOM
#   include "vscf_fake_random.h"
#endif

#if VSCF_FALCON
#   include "vscf_falcon.h"
#endif

#if VSCF_FOOTER_INFO
#   include "vscf_footer_info.h"
#endif

#if VSCF_GROUP_SESSION
#   include "vscf_group_session.h"
#endif

#if VSCF_GROUP_SESSION_MESSAGE
#   include "vscf_group_session_message.h"
#endif

#if VSCF_GROUP_SESSION_TICKET
#   include "vscf_group_session_ticket.h"
#endif

#if VSCF_HASH
#   include "vscf_hash.h"
#endif

#if VSCF_HASH_BASED_ALG_INFO
#   include "vscf_hash_based_alg_info.h"
#endif

#if VSCF_HKDF
#   include "vscf_hkdf.h"
#endif

#if VSCF_HMAC
#   include "vscf_hmac.h"
#endif

#if VSCF_HYBRID_KEY_ALG
#   include "vscf_hybrid_key_alg.h"
#endif

#if VSCF_HYBRID_KEY_ALG_INFO
#   include "vscf_hybrid_key_alg_info.h"
#endif

#if VSCF_HYBRID_PRIVATE_KEY
#   include "vscf_hybrid_private_key.h"
#endif

#if VSCF_HYBRID_PUBLIC_KEY
#   include "vscf_hybrid_public_key.h"
#endif

#if VSCF_KDF
#   include "vscf_kdf.h"
#endif

#if VSCF_KDF1
#   include "vscf_kdf1.h"
#endif

#if VSCF_KDF2
#   include "vscf_kdf2.h"
#endif

#if VSCF_KEM
#   include "vscf_kem.h"
#endif

#if VSCF_KEY
#   include "vscf_key.h"
#endif

#if VSCF_KEY_ALG
#   include "vscf_key_alg.h"
#endif

#if VSCF_KEY_ALG_FACTORY
#   include "vscf_key_alg_factory.h"
#endif

#if VSCF_KEY_ASN1_DESERIALIZER
#   include "vscf_key_asn1_deserializer.h"
#endif

#if VSCF_KEY_ASN1_SERIALIZER
#   include "vscf_key_asn1_serializer.h"
#endif

#if VSCF_KEY_CIPHER
#   include "vscf_key_cipher.h"
#endif

#if VSCF_KEY_DESERIALIZER
#   include "vscf_key_deserializer.h"
#endif

#if VSCF_KEY_INFO
#   include "vscf_key_info.h"
#endif

#if VSCF_KEY_MATERIAL_RNG
#   include "vscf_key_material_rng.h"
#endif

#if VSCF_KEY_PROVIDER
#   include "vscf_key_provider.h"
#endif

#if VSCF_KEY_RECIPIENT_INFO
#   include "vscf_key_recipient_info.h"
#endif

#if VSCF_KEY_RECIPIENT_INFO_LIST
#   include "vscf_key_recipient_info_list.h"
#endif

#if VSCF_KEY_SERIALIZER
#   include "vscf_key_serializer.h"
#endif

#if VSCF_KEY_SIGNER
#   include "vscf_key_signer.h"
#endif

#if VSCF_MAC
#   include "vscf_mac.h"
#endif

#if VSCF_MESSAGE_INFO
#   include "vscf_message_info.h"
#endif

#if VSCF_MESSAGE_INFO_CUSTOM_PARAMS
#   include "vscf_message_info_custom_params.h"
#endif

#if VSCF_MESSAGE_INFO_DER_SERIALIZER
#   include "vscf_message_info_der_serializer.h"
#endif

#if VSCF_MESSAGE_INFO_EDITOR
#   include "vscf_message_info_editor.h"
#endif

#if VSCF_MESSAGE_INFO_FOOTER
#   include "vscf_message_info_footer.h"
#endif

#if VSCF_MESSAGE_INFO_FOOTER_SERIALIZER
#   include "vscf_message_info_footer_serializer.h"
#endif

#if VSCF_MESSAGE_INFO_SERIALIZER
#   include "vscf_message_info_serializer.h"
#endif

#if VSCF_OID
#   include "vscf_oid.h"
#endif

#if VSCF_PADDING
#   include "vscf_padding.h"
#endif

#if VSCF_PADDING_PARAMS
#   include "vscf_padding_params.h"
#endif

#if VSCF_PASSWORD_RECIPIENT_INFO
#   include "vscf_password_recipient_info.h"
#endif

#if VSCF_PASSWORD_RECIPIENT_INFO_LIST
#   include "vscf_password_recipient_info_list.h"
#endif

#if VSCF_PBE_ALG_INFO
#   include "vscf_pbe_alg_info.h"
#endif

#if VSCF_PEM
#   include "vscf_pem.h"
#endif

#if VSCF_PKCS5_PBES2
#   include "vscf_pkcs5_pbes2.h"
#endif

#if VSCF_PKCS5_PBKDF2
#   include "vscf_pkcs5_pbkdf2.h"
#endif

#if VSCF_PKCS8_SERIALIZER
#   include "vscf_pkcs8_serializer.h"
#endif

#if VSCF_PRIVATE_KEY
#   include "vscf_private_key.h"
#endif

#if VSCF_PUBLIC_KEY
#   include "vscf_public_key.h"
#endif

#if VSCF_RANDOM
#   include "vscf_random.h"
#endif

#if VSCF_RANDOM_PADDING
#   include "vscf_random_padding.h"
#endif

#if VSCF_RAW_PRIVATE_KEY
#   include "vscf_raw_private_key.h"
#endif

#if VSCF_RAW_PUBLIC_KEY
#   include "vscf_raw_public_key.h"
#endif

#if VSCF_RECIPIENT_CIPHER
#   include "vscf_recipient_cipher.h"
#endif

#if VSCF_ROUND5
#   include "vscf_round5.h"
#endif

#if VSCF_RSA
#   include "vscf_rsa.h"
#endif

#if VSCF_RSA_PRIVATE_KEY
#   include "vscf_rsa_private_key.h"
#endif

#if VSCF_RSA_PUBLIC_KEY
#   include "vscf_rsa_public_key.h"
#endif

#if VSCF_SALTED_KDF
#   include "vscf_salted_kdf.h"
#endif

#if VSCF_SALTED_KDF_ALG_INFO
#   include "vscf_salted_kdf_alg_info.h"
#endif

#if VSCF_SEC1_SERIALIZER
#   include "vscf_sec1_serializer.h"
#endif

#if VSCF_SEED_ENTROPY_SOURCE
#   include "vscf_seed_entropy_source.h"
#endif

#if VSCF_SHA224
#   include "vscf_sha224.h"
#endif

#if VSCF_SHA256
#   include "vscf_sha256.h"
#endif

#if VSCF_SHA384
#   include "vscf_sha384.h"
#endif

#if VSCF_SHA512
#   include "vscf_sha512.h"
#endif

#if VSCF_SIGNED_DATA_INFO
#   include "vscf_signed_data_info.h"
#endif

#if VSCF_SIGNER
#   include "vscf_signer.h"
#endif

#if VSCF_SIGNER_INFO
#   include "vscf_signer_info.h"
#endif

#if VSCF_SIGNER_INFO_LIST
#   include "vscf_signer_info_list.h"
#endif

#if VSCF_SIMPLE_ALG_INFO
#   include "vscf_simple_alg_info.h"
#endif

#if VSCF_VERIFIER
#   include "vscf_verifier.h"
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
#endif // VSCF_FOUNDATION_PUBLIC_H_INCLUDED
//  @end
