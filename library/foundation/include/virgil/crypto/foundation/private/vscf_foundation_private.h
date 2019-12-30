//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#include "vscf_aes256_cbc_defs.h"
#include "vscf_aes256_gcm_defs.h"
#include "vscf_alg_api.h"
#include "vscf_alg_info_api.h"
#include "vscf_alg_info_der_deserializer_defs.h"
#include "vscf_alg_info_der_serializer_defs.h"
#include "vscf_alg_info_deserializer_api.h"
#include "vscf_alg_info_serializer_api.h"
#include "vscf_api_private.h"
#include "vscf_asn1_reader_api.h"
#include "vscf_asn1_writer_api.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_atomic.h"
#include "vscf_auth_decrypt_api.h"
#include "vscf_auth_encrypt_api.h"
#include "vscf_cipher_alg_info_defs.h"
#include "vscf_cipher_api.h"
#include "vscf_cipher_auth_api.h"
#include "vscf_cipher_auth_info_api.h"
#include "vscf_cipher_info_api.h"
#include "vscf_compound_key_alg_defs.h"
#include "vscf_compound_key_alg_info_defs.h"
#include "vscf_compound_private_key_defs.h"
#include "vscf_compound_public_key_defs.h"
#include "vscf_compute_shared_key_api.h"
#include "vscf_ctr_drbg_defs.h"
#include "vscf_curve25519_defs.h"
#include "vscf_decrypt_api.h"
#include "vscf_ecc_alg_info_defs.h"
#include "vscf_ecc_defs.h"
#include "vscf_ecc_private_key_defs.h"
#include "vscf_ecc_public_key_defs.h"
#include "vscf_ecies_defs.h"
#include "vscf_ed25519_defs.h"
#include "vscf_encrypt_api.h"
#include "vscf_entropy_accumulator_defs.h"
#include "vscf_entropy_source_api.h"
#include "vscf_fake_random_defs.h"
#include "vscf_falcon_defs.h"
#include "vscf_footer_info_defs.h"
#include "vscf_group_session_message_defs.h"
#include "vscf_group_session_ticket_defs.h"
#include "vscf_hash_api.h"
#include "vscf_hash_based_alg_info_defs.h"
#include "vscf_hkdf_defs.h"
#include "vscf_hkdf_private.h"
#include "vscf_hmac_defs.h"
#include "vscf_hybrid_key_alg_defs.h"
#include "vscf_hybrid_key_alg_info_defs.h"
#include "vscf_hybrid_private_key_defs.h"
#include "vscf_hybrid_public_key_defs.h"
#include "vscf_impl_private.h"
#include "vscf_kdf_api.h"
#include "vscf_kdf1_defs.h"
#include "vscf_kdf2_defs.h"
#include "vscf_kem_api.h"
#include "vscf_key_alg_api.h"
#include "vscf_key_api.h"
#include "vscf_key_asn1_deserializer_defs.h"
#include "vscf_key_asn1_serializer_defs.h"
#include "vscf_key_cipher_api.h"
#include "vscf_key_deserializer_api.h"
#include "vscf_key_info_defs.h"
#include "vscf_key_material_rng_defs.h"
#include "vscf_key_provider_defs.h"
#include "vscf_key_recipient_info_defs.h"
#include "vscf_key_recipient_info_list_defs.h"
#include "vscf_key_serializer_api.h"
#include "vscf_key_signer_api.h"
#include "vscf_mac_api.h"
#include "vscf_mbedtls_bridge_entropy.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_message_cipher.h"
#include "vscf_message_info_custom_params_defs.h"
#include "vscf_message_info_defs.h"
#include "vscf_message_info_der_serializer_defs.h"
#include "vscf_message_info_editor_defs.h"
#include "vscf_message_info_footer_defs.h"
#include "vscf_message_info_footer_serializer_api.h"
#include "vscf_message_info_serializer_api.h"
#include "vscf_message_padding.h"
#include "vscf_padding_api.h"
#include "vscf_padding_params_defs.h"
#include "vscf_password_recipient_info_defs.h"
#include "vscf_password_recipient_info_list_defs.h"
#include "vscf_pbe_alg_info_defs.h"
#include "vscf_pkcs5_pbes2_defs.h"
#include "vscf_pkcs5_pbkdf2_defs.h"
#include "vscf_pkcs8_serializer_defs.h"
#include "vscf_private_key_api.h"
#include "vscf_public_key_api.h"
#include "vscf_random_api.h"
#include "vscf_random_padding_defs.h"
#include "vscf_raw_private_key_defs.h"
#include "vscf_raw_public_key_defs.h"
#include "vscf_recipient_cipher_decryption_state.h"
#include "vscf_recipient_cipher_defs.h"
#include "vscf_round5_defs.h"
#include "vscf_rsa_defs.h"
#include "vscf_rsa_private_key_defs.h"
#include "vscf_rsa_public_key_defs.h"
#include "vscf_salted_kdf_alg_info_defs.h"
#include "vscf_salted_kdf_api.h"
#include "vscf_sec1_serializer_defs.h"
#include "vscf_seed_entropy_source_defs.h"
#include "vscf_sha224_defs.h"
#include "vscf_sha256_defs.h"
#include "vscf_sha384_defs.h"
#include "vscf_sha512_defs.h"
#include "vscf_signed_data_info_defs.h"
#include "vscf_signer_defs.h"
#include "vscf_signer_info_defs.h"
#include "vscf_signer_info_list_defs.h"
#include "vscf_simple_alg_info_defs.h"
#include "vscf_simple_swu.h"
#include "vscf_verifier_defs.h"

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
