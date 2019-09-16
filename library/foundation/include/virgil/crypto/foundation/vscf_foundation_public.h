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
//  This ia an umbrella header that includes library public headers.
// --------------------------------------------------------------------------

#ifndef VSCF_FOUNDATION_PUBLIC_H_INCLUDED
#define VSCF_FOUNDATION_PUBLIC_H_INCLUDED

#include "vscf_aes256_cbc.h"
#include "vscf_aes256_gcm.h"
#include "vscf_alg.h"
#include "vscf_alg_factory.h"
#include "vscf_alg_id.h"
#include "vscf_alg_info.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_deserializer.h"
#include "vscf_alg_info_serializer.h"
#include "vscf_api.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_assert.h"
#include "vscf_auth_decrypt.h"
#include "vscf_auth_encrypt.h"
#include "vscf_base64.h"
#include "vscf_brainkey_client.h"
#include "vscf_brainkey_server.h"
#include "vscf_cipher.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_cipher_auth.h"
#include "vscf_cipher_auth_info.h"
#include "vscf_cipher_info.h"
#include "vscf_compute_shared_key.h"
#include "vscf_ctr_drbg.h"
#include "vscf_curve25519.h"
#include "vscf_decrypt.h"
#include "vscf_ecc.h"
#include "vscf_ecc_alg_info.h"
#include "vscf_ecc_private_key.h"
#include "vscf_ecc_public_key.h"
#include "vscf_ecies.h"
#include "vscf_ed25519.h"
#include "vscf_encrypt.h"
#include "vscf_entropy_accumulator.h"
#include "vscf_entropy_source.h"
#include "vscf_error.h"
#include "vscf_fake_random.h"
#include "vscf_group_msg_type.h"
#include "vscf_group_session.h"
#include "vscf_group_session_message.h"
#include "vscf_group_session_ticket.h"
#include "vscf_hash.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_hkdf.h"
#include "vscf_hmac.h"
#include "vscf_impl.h"
#include "vscf_kdf.h"
#include "vscf_kdf1.h"
#include "vscf_kdf2.h"
#include "vscf_key.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_factory.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_key_asn1_serializer.h"
#include "vscf_key_cipher.h"
#include "vscf_key_deserializer.h"
#include "vscf_key_material_rng.h"
#include "vscf_key_provider.h"
#include "vscf_key_recipient_info.h"
#include "vscf_key_recipient_info_list.h"
#include "vscf_key_serializer.h"
#include "vscf_key_signer.h"
#include "vscf_library.h"
#include "vscf_mac.h"
#include "vscf_memory.h"
#include "vscf_message_info.h"
#include "vscf_message_info_custom_params.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_message_info_editor.h"
#include "vscf_message_info_serializer.h"
#include "vscf_oid.h"
#include "vscf_oid_id.h"
#include "vscf_password_recipient_info.h"
#include "vscf_password_recipient_info_list.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_pem.h"
#include "vscf_pkcs5_pbes2.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_pkcs8_serializer.h"
#include "vscf_platform.h"
#include "vscf_private_key.h"
#include "vscf_public_key.h"
#include "vscf_random.h"
#include "vscf_raw_private_key.h"
#include "vscf_raw_public_key.h"
#include "vscf_recipient_cipher.h"
#include "vscf_rsa.h"
#include "vscf_rsa_private_key.h"
#include "vscf_rsa_public_key.h"
#include "vscf_salted_kdf.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_sec1_serializer.h"
#include "vscf_seed_entropy_source.h"
#include "vscf_sha224.h"
#include "vscf_sha256.h"
#include "vscf_sha384.h"
#include "vscf_sha512.h"
#include "vscf_signer.h"
#include "vscf_simple_alg_info.h"
#include "vscf_status.h"
#include "vscf_verifier.h"

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
