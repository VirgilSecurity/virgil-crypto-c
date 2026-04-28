//
// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

#ifndef VSCF_FOUNDATION_PHP_H_INCLUDED
#define VSCF_FOUNDATION_PHP_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif


#if defined(_WIN32) || defined(__CYGWIN__)
#   if VSCF_PHP_SHARED_LIBRARY
#       if defined(VSCF_PHP_INTERNAL_BUILD)
#           ifdef __GNUC__
#               define VSCF_PHP_PUBLIC __attribute__ ((dllexport))
#           else
#               define VSCF_PHP_PUBLIC __declspec(dllexport)
#           endif
#       else
#           ifdef __GNUC__
#               define VSCF_PHP_PUBLIC __attribute__ ((dllimport))
#           else
#               define VSCF_PHP_PUBLIC __declspec(dllimport)
#           endif
#       endif
#   else
#       define VSCF_PHP_PUBLIC
#   endif
#   define VSCF_PHP_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define VSCF_PHP_PUBLIC __attribute__ ((visibility ("default")))
#       define VSCF_PHP_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSCF_PHP_PRIVATE
#   endif
#endif

//
// Constants
//
VSCF_PHP_PUBLIC const char*
vscf_impl_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_aes256_cbc_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_aes256_gcm_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_alg_info_der_deserializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_alg_info_der_serializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_asn1rd_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_asn1wr_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_brainkey_client_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_brainkey_server_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_cipher_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_compound_key_alg_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_compound_key_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_compound_private_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_compound_public_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ctr_drbg_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_curve25519_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecc_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecc_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecc_private_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecc_public_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ecies_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ed25519_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_entropy_accumulator_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_fake_random_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_falcon_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_footer_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_message_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_group_session_ticket_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hash_based_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hkdf_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hmac_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hybrid_key_alg_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hybrid_key_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hybrid_private_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_hybrid_public_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_kdf1_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_kdf2_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_asn1_deserializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_asn1_serializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_material_rng_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_provider_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_recipient_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_key_recipient_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_custom_params_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_der_serializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_editor_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_message_info_footer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ml_dsa_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_ml_kem_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_padding_params_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_password_recipient_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_password_recipient_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_pbe_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_pkcs5_pbes2_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_pkcs5_pbkdf2_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_pkcs8_serializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_random_padding_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_raw_private_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_raw_public_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_recipient_cipher_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_rsa_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_rsa_private_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_rsa_public_key_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_salted_kdf_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_sec1_serializer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_seed_entropy_source_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_sha224_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_sha256_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_sha384_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_sha512_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signed_data_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_signer_info_list_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_simple_alg_info_t_php_res_name(void);

VSCF_PHP_PUBLIC const char*
vscf_verifier_t_php_res_name(void);

//
// Registered resources
//
VSCF_PHP_PUBLIC int
le_vscf_impl_t(void);

VSCF_PHP_PUBLIC int
le_vscf_aes256_cbc_t(void);

VSCF_PHP_PUBLIC int
le_vscf_aes256_gcm_t(void);

VSCF_PHP_PUBLIC int
le_vscf_alg_info_der_deserializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_alg_info_der_serializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_asn1rd_t(void);

VSCF_PHP_PUBLIC int
le_vscf_asn1wr_t(void);

VSCF_PHP_PUBLIC int
le_vscf_brainkey_client_t(void);

VSCF_PHP_PUBLIC int
le_vscf_brainkey_server_t(void);

VSCF_PHP_PUBLIC int
le_vscf_cipher_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_compound_key_alg_t(void);

VSCF_PHP_PUBLIC int
le_vscf_compound_key_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_compound_private_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_compound_public_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ctr_drbg_t(void);

VSCF_PHP_PUBLIC int
le_vscf_curve25519_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecc_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecc_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecc_private_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecc_public_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ecies_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ed25519_t(void);

VSCF_PHP_PUBLIC int
le_vscf_entropy_accumulator_t(void);

VSCF_PHP_PUBLIC int
le_vscf_fake_random_t(void);

VSCF_PHP_PUBLIC int
le_vscf_falcon_t(void);

VSCF_PHP_PUBLIC int
le_vscf_footer_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_message_t(void);

VSCF_PHP_PUBLIC int
le_vscf_group_session_ticket_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hash_based_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hkdf_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hmac_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hybrid_key_alg_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hybrid_key_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hybrid_private_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_hybrid_public_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_kdf1_t(void);

VSCF_PHP_PUBLIC int
le_vscf_kdf2_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_asn1_deserializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_asn1_serializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_material_rng_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_provider_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_recipient_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_key_recipient_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_custom_params_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_der_serializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_editor_t(void);

VSCF_PHP_PUBLIC int
le_vscf_message_info_footer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ml_dsa_t(void);

VSCF_PHP_PUBLIC int
le_vscf_ml_kem_t(void);

VSCF_PHP_PUBLIC int
le_vscf_padding_params_t(void);

VSCF_PHP_PUBLIC int
le_vscf_password_recipient_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_password_recipient_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_pbe_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_pkcs5_pbes2_t(void);

VSCF_PHP_PUBLIC int
le_vscf_pkcs5_pbkdf2_t(void);

VSCF_PHP_PUBLIC int
le_vscf_pkcs8_serializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_random_padding_t(void);

VSCF_PHP_PUBLIC int
le_vscf_raw_private_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_raw_public_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_recipient_cipher_t(void);

VSCF_PHP_PUBLIC int
le_vscf_rsa_t(void);

VSCF_PHP_PUBLIC int
le_vscf_rsa_private_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_rsa_public_key_t(void);

VSCF_PHP_PUBLIC int
le_vscf_salted_kdf_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_sec1_serializer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_seed_entropy_source_t(void);

VSCF_PHP_PUBLIC int
le_vscf_sha224_t(void);

VSCF_PHP_PUBLIC int
le_vscf_sha256_t(void);

VSCF_PHP_PUBLIC int
le_vscf_sha384_t(void);

VSCF_PHP_PUBLIC int
le_vscf_sha512_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signed_data_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_signer_info_list_t(void);

VSCF_PHP_PUBLIC int
le_vscf_simple_alg_info_t(void);

VSCF_PHP_PUBLIC int
le_vscf_verifier_t(void);

#ifdef __cplusplus
}
#endif

#endif // VSCF_FOUNDATION_PHP_H_INCLUDED
