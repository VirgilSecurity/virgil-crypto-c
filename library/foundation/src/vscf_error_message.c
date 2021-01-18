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


//  @description
// --------------------------------------------------------------------------
//  Provide error and status messages.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_error_message.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const char k_message_unknown_error_chars[] = "Unknown error.";

static const vsc_str_t k_message_unknown_error = {
    k_message_unknown_error_chars,
    sizeof(k_message_unknown_error_chars) - 1
};

static const char k_message_success_chars[] = "No errors was occurred.";

static const vsc_str_t k_message_success = {
    k_message_success_chars,
    sizeof(k_message_success_chars) - 1
};

static const char k_message_error_bad_arguments_chars[] = "This error should not be returned if assertions is enabled.";

static const vsc_str_t k_message_error_bad_arguments = {
    k_message_error_bad_arguments_chars,
    sizeof(k_message_error_bad_arguments_chars) - 1
};

static const char k_message_error_uninitialized_chars[] = "Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.";

static const vsc_str_t k_message_error_uninitialized = {
    k_message_error_uninitialized_chars,
    sizeof(k_message_error_uninitialized_chars) - 1
};

static const char k_message_error_unhandled_thirdparty_error_chars[] = "Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.";

static const vsc_str_t k_message_error_unhandled_thirdparty_error = {
    k_message_error_unhandled_thirdparty_error_chars,
    sizeof(k_message_error_unhandled_thirdparty_error_chars) - 1
};

static const char k_message_error_small_buffer_chars[] = "Buffer capacity is not enough to hold result.";

static const vsc_str_t k_message_error_small_buffer = {
    k_message_error_small_buffer_chars,
    sizeof(k_message_error_small_buffer_chars) - 1
};

static const char k_message_hex_to_bytes_failed_chars[] = "Convertion from HEX string to the byte array failed.";

static const vsc_str_t k_message_hex_to_bytes_failed = {
    k_message_hex_to_bytes_failed_chars,
    sizeof(k_message_hex_to_bytes_failed_chars) - 1
};

static const char k_message_error_unsupported_algorithm_chars[] = "Unsupported algorithm.";

static const vsc_str_t k_message_error_unsupported_algorithm = {
    k_message_error_unsupported_algorithm_chars,
    sizeof(k_message_error_unsupported_algorithm_chars) - 1
};

static const char k_message_error_auth_failed_chars[] = "Authentication failed during decryption.";

static const vsc_str_t k_message_error_auth_failed = {
    k_message_error_auth_failed_chars,
    sizeof(k_message_error_auth_failed_chars) - 1
};

static const char k_message_error_out_of_data_chars[] = "Attempt to read data out of buffer bounds.";

static const vsc_str_t k_message_error_out_of_data = {
    k_message_error_out_of_data_chars,
    sizeof(k_message_error_out_of_data_chars) - 1
};

static const char k_message_error_bad_asn1_chars[] = "ASN.1 encoded data is corrupted.";

static const vsc_str_t k_message_error_bad_asn1 = {
    k_message_error_bad_asn1_chars,
    sizeof(k_message_error_bad_asn1_chars) - 1
};

static const char k_message_error_asn1_lossy_type_narrowing_chars[] = "Attempt to read ASN.1 type that is bigger then requested C type.";

static const vsc_str_t k_message_error_asn1_lossy_type_narrowing = {
    k_message_error_asn1_lossy_type_narrowing_chars,
    sizeof(k_message_error_asn1_lossy_type_narrowing_chars) - 1
};

static const char k_message_error_bad_pkcs1_public_key_chars[] = "ASN.1 representation of PKCS#1 public key is corrupted.";

static const vsc_str_t k_message_error_bad_pkcs1_public_key = {
    k_message_error_bad_pkcs1_public_key_chars,
    sizeof(k_message_error_bad_pkcs1_public_key_chars) - 1
};

static const char k_message_error_bad_pkcs1_private_key_chars[] = "ASN.1 representation of PKCS#1 private key is corrupted.";

static const vsc_str_t k_message_error_bad_pkcs1_private_key = {
    k_message_error_bad_pkcs1_private_key_chars,
    sizeof(k_message_error_bad_pkcs1_private_key_chars) - 1
};

static const char k_message_error_bad_pkcs8_public_key_chars[] = "ASN.1 representation of PKCS#8 public key is corrupted.";

static const vsc_str_t k_message_error_bad_pkcs8_public_key = {
    k_message_error_bad_pkcs8_public_key_chars,
    sizeof(k_message_error_bad_pkcs8_public_key_chars) - 1
};

static const char k_message_error_bad_pkcs8_private_key_chars[] = "ASN.1 representation of PKCS#8 private key is corrupted.";

static const vsc_str_t k_message_error_bad_pkcs8_private_key = {
    k_message_error_bad_pkcs8_private_key_chars,
    sizeof(k_message_error_bad_pkcs8_private_key_chars) - 1
};

static const char k_message_error_bad_encrypted_data_chars[] = "Encrypted data is corrupted.";

static const vsc_str_t k_message_error_bad_encrypted_data = {
    k_message_error_bad_encrypted_data_chars,
    sizeof(k_message_error_bad_encrypted_data_chars) - 1
};

static const char k_message_error_random_failed_chars[] = "Underlying random operation returns error.";

static const vsc_str_t k_message_error_random_failed = {
    k_message_error_random_failed_chars,
    sizeof(k_message_error_random_failed_chars) - 1
};

static const char k_message_error_key_generation_failed_chars[] = "Generation of the private or secret key failed.";

static const vsc_str_t k_message_error_key_generation_failed = {
    k_message_error_key_generation_failed_chars,
    sizeof(k_message_error_key_generation_failed_chars) - 1
};

static const char k_message_error_entropy_source_failed_chars[] = "One of the entropy sources failed.";

static const vsc_str_t k_message_error_entropy_source_failed = {
    k_message_error_entropy_source_failed_chars,
    sizeof(k_message_error_entropy_source_failed_chars) - 1
};

static const char k_message_error_rng_requested_data_too_big_chars[] = "Requested data to be generated is too big.";

static const vsc_str_t k_message_error_rng_requested_data_too_big = {
    k_message_error_rng_requested_data_too_big_chars,
    sizeof(k_message_error_rng_requested_data_too_big_chars) - 1
};

static const char k_message_error_bad_base64_chars[] = "Base64 encoded string contains invalid characters.";

static const vsc_str_t k_message_error_bad_base64 = {
    k_message_error_bad_base64_chars,
    sizeof(k_message_error_bad_base64_chars) - 1
};

static const char k_message_error_bad_pem_chars[] = "PEM data is corrupted.";

static const vsc_str_t k_message_error_bad_pem = {
    k_message_error_bad_pem_chars,
    sizeof(k_message_error_bad_pem_chars) - 1
};

static const char k_message_error_shared_key_exchange_failed_chars[] = "Exchange key return zero.";

static const vsc_str_t k_message_error_shared_key_exchange_failed = {
    k_message_error_shared_key_exchange_failed_chars,
    sizeof(k_message_error_shared_key_exchange_failed_chars) - 1
};

static const char k_message_error_bad_ed25519_public_key_chars[] = "Ed25519 public key is corrupted.";

static const vsc_str_t k_message_error_bad_ed25519_public_key = {
    k_message_error_bad_ed25519_public_key_chars,
    sizeof(k_message_error_bad_ed25519_public_key_chars) - 1
};

static const char k_message_error_bad_ed25519_private_key_chars[] = "Ed25519 private key is corrupted.";

static const vsc_str_t k_message_error_bad_ed25519_private_key = {
    k_message_error_bad_ed25519_private_key_chars,
    sizeof(k_message_error_bad_ed25519_private_key_chars) - 1
};

static const char k_message_error_bad_curve25519_public_key_chars[] = "CURVE25519 public key is corrupted.";

static const vsc_str_t k_message_error_bad_curve25519_public_key = {
    k_message_error_bad_curve25519_public_key_chars,
    sizeof(k_message_error_bad_curve25519_public_key_chars) - 1
};

static const char k_message_error_bad_curve25519_private_key_chars[] = "CURVE25519 private key is corrupted.";

static const vsc_str_t k_message_error_bad_curve25519_private_key = {
    k_message_error_bad_curve25519_private_key_chars,
    sizeof(k_message_error_bad_curve25519_private_key_chars) - 1
};

static const char k_message_error_bad_sec1_public_key_chars[] = "Elliptic curve public key format is corrupted see RFC 5480.";

static const vsc_str_t k_message_error_bad_sec1_public_key = {
    k_message_error_bad_sec1_public_key_chars,
    sizeof(k_message_error_bad_sec1_public_key_chars) - 1
};

static const char k_message_error_bad_sec1_private_key_chars[] = "Elliptic curve public key format is corrupted see RFC 5915.";

static const vsc_str_t k_message_error_bad_sec1_private_key = {
    k_message_error_bad_sec1_private_key_chars,
    sizeof(k_message_error_bad_sec1_private_key_chars) - 1
};

static const char k_message_error_bad_der_public_key_chars[] = "ASN.1 representation of a public key is corrupted.";

static const vsc_str_t k_message_error_bad_der_public_key = {
    k_message_error_bad_der_public_key_chars,
    sizeof(k_message_error_bad_der_public_key_chars) - 1
};

static const char k_message_error_bad_der_private_key_chars[] = "ASN.1 representation of a private key is corrupted.";

static const vsc_str_t k_message_error_bad_der_private_key = {
    k_message_error_bad_der_private_key_chars,
    sizeof(k_message_error_bad_der_private_key_chars) - 1
};

static const char k_message_error_mismatch_public_key_and_algorithm_chars[] = "Key algorithm does not accept given type of public key.";

static const vsc_str_t k_message_error_mismatch_public_key_and_algorithm = {
    k_message_error_mismatch_public_key_and_algorithm_chars,
    sizeof(k_message_error_mismatch_public_key_and_algorithm_chars) - 1
};

static const char k_message_error_mismatch_private_key_and_algorithm_chars[] = "Key algorithm does not accept given type of private key.";

static const vsc_str_t k_message_error_mismatch_private_key_and_algorithm = {
    k_message_error_mismatch_private_key_and_algorithm_chars,
    sizeof(k_message_error_mismatch_private_key_and_algorithm_chars) - 1
};

static const char k_message_error_bad_falcon_public_key_chars[] = "Post-quantum Falcon-Sign public key is corrupted.";

static const vsc_str_t k_message_error_bad_falcon_public_key = {
    k_message_error_bad_falcon_public_key_chars,
    sizeof(k_message_error_bad_falcon_public_key_chars) - 1
};

static const char k_message_error_bad_falcon_private_key_chars[] = "Post-quantum Falcon-Sign private key is corrupted.";

static const vsc_str_t k_message_error_bad_falcon_private_key = {
    k_message_error_bad_falcon_private_key_chars,
    sizeof(k_message_error_bad_falcon_private_key_chars) - 1
};

static const char k_message_error_round5_chars[] = "Generic Round5 library error.";

static const vsc_str_t k_message_error_round5 = {
    k_message_error_round5_chars,
    sizeof(k_message_error_round5_chars) - 1
};

static const char k_message_error_bad_round5_public_key_chars[] = "Post-quantum NIST Round5 public key is corrupted.";

static const vsc_str_t k_message_error_bad_round5_public_key = {
    k_message_error_bad_round5_public_key_chars,
    sizeof(k_message_error_bad_round5_public_key_chars) - 1
};

static const char k_message_error_bad_round5_private_key_chars[] = "Post-quantum NIST Round5 private key is corrupted.";

static const vsc_str_t k_message_error_bad_round5_private_key = {
    k_message_error_bad_round5_private_key_chars,
    sizeof(k_message_error_bad_round5_private_key_chars) - 1
};

static const char k_message_error_bad_compound_public_key_chars[] = "Compound public key is corrupted.";

static const vsc_str_t k_message_error_bad_compound_public_key = {
    k_message_error_bad_compound_public_key_chars,
    sizeof(k_message_error_bad_compound_public_key_chars) - 1
};

static const char k_message_error_bad_compound_private_key_chars[] = "Compound private key is corrupted.";

static const vsc_str_t k_message_error_bad_compound_private_key = {
    k_message_error_bad_compound_private_key_chars,
    sizeof(k_message_error_bad_compound_private_key_chars) - 1
};

static const char k_message_error_bad_hybrid_public_key_chars[] = "Compound public hybrid key is corrupted.";

static const vsc_str_t k_message_error_bad_hybrid_public_key = {
    k_message_error_bad_hybrid_public_key_chars,
    sizeof(k_message_error_bad_hybrid_public_key_chars) - 1
};

static const char k_message_error_bad_hybrid_private_key_chars[] = "Compound private hybrid key is corrupted.";

static const vsc_str_t k_message_error_bad_hybrid_private_key = {
    k_message_error_bad_hybrid_private_key_chars,
    sizeof(k_message_error_bad_hybrid_private_key_chars) - 1
};

static const char k_message_error_bad_asn1_algorithm_chars[] = "ASN.1 AlgorithmIdentifer is corrupted.";

static const vsc_str_t k_message_error_bad_asn1_algorithm = {
    k_message_error_bad_asn1_algorithm_chars,
    sizeof(k_message_error_bad_asn1_algorithm_chars) - 1
};

static const char k_message_error_bad_asn1_algorithm_ecc_chars[] = "ASN.1 AlgorithmIdentifer with ECParameters is corrupted.";

static const vsc_str_t k_message_error_bad_asn1_algorithm_ecc = {
    k_message_error_bad_asn1_algorithm_ecc_chars,
    sizeof(k_message_error_bad_asn1_algorithm_ecc_chars) - 1
};

static const char k_message_error_bad_asn1_algorithm_compound_key_chars[] = "ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.";

static const vsc_str_t k_message_error_bad_asn1_algorithm_compound_key = {
    k_message_error_bad_asn1_algorithm_compound_key_chars,
    sizeof(k_message_error_bad_asn1_algorithm_compound_key_chars) - 1
};

static const char k_message_error_bad_asn1_algorithm_hybrid_key_chars[] = "ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.";

static const vsc_str_t k_message_error_bad_asn1_algorithm_hybrid_key = {
    k_message_error_bad_asn1_algorithm_hybrid_key_chars,
    sizeof(k_message_error_bad_asn1_algorithm_hybrid_key_chars) - 1
};

static const char k_message_error_no_message_info_chars[] = "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.";

static const vsc_str_t k_message_error_no_message_info = {
    k_message_error_no_message_info_chars,
    sizeof(k_message_error_no_message_info_chars) - 1
};

static const char k_message_error_bad_message_info_chars[] = "Message Info is corrupted.";

static const vsc_str_t k_message_error_bad_message_info = {
    k_message_error_bad_message_info_chars,
    sizeof(k_message_error_bad_message_info_chars) - 1
};

static const char k_message_error_key_recipient_is_not_found_chars[] = "Recipient defined with id is not found within message info during data decryption.";

static const vsc_str_t k_message_error_key_recipient_is_not_found = {
    k_message_error_key_recipient_is_not_found_chars,
    sizeof(k_message_error_key_recipient_is_not_found_chars) - 1
};

static const char k_message_error_key_recipient_private_key_is_wrong_chars[] = "Content encryption key can not be decrypted with a given private key.";

static const vsc_str_t k_message_error_key_recipient_private_key_is_wrong = {
    k_message_error_key_recipient_private_key_is_wrong_chars,
    sizeof(k_message_error_key_recipient_private_key_is_wrong_chars) - 1
};

static const char k_message_error_password_recipient_password_is_wrong_chars[] = "Content encryption key can not be decrypted with a given password.";

static const vsc_str_t k_message_error_password_recipient_password_is_wrong = {
    k_message_error_password_recipient_password_is_wrong_chars,
    sizeof(k_message_error_password_recipient_password_is_wrong_chars) - 1
};

static const char k_message_error_message_info_custom_param_not_found_chars[] = "Custom parameter with a given key is not found within message info.";

static const vsc_str_t k_message_error_message_info_custom_param_not_found = {
    k_message_error_message_info_custom_param_not_found_chars,
    sizeof(k_message_error_message_info_custom_param_not_found_chars) - 1
};

static const char k_message_error_message_info_custom_param_type_mismatch_chars[] = "A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.";

static const vsc_str_t k_message_error_message_info_custom_param_type_mismatch = {
    k_message_error_message_info_custom_param_type_mismatch_chars,
    sizeof(k_message_error_message_info_custom_param_type_mismatch_chars) - 1
};

static const char k_message_error_bad_signature_chars[] = "Signature format is corrupted.";

static const vsc_str_t k_message_error_bad_signature = {
    k_message_error_bad_signature_chars,
    sizeof(k_message_error_bad_signature_chars) - 1
};

static const char k_message_error_bad_message_info_footer_chars[] = "Message Info footer is corrupted.";

static const vsc_str_t k_message_error_bad_message_info_footer = {
    k_message_error_bad_message_info_footer_chars,
    sizeof(k_message_error_bad_message_info_footer_chars) - 1
};

static const char k_message_error_invalid_brainkey_password_len_chars[] = "Brainkey password length is out of range.";

static const vsc_str_t k_message_error_invalid_brainkey_password_len = {
    k_message_error_invalid_brainkey_password_len_chars,
    sizeof(k_message_error_invalid_brainkey_password_len_chars) - 1
};

static const char k_message_error_invalid_brainkey_factor_len_chars[] = "Brainkey number length should be 32 byte.";

static const vsc_str_t k_message_error_invalid_brainkey_factor_len = {
    k_message_error_invalid_brainkey_factor_len_chars,
    sizeof(k_message_error_invalid_brainkey_factor_len_chars) - 1
};

static const char k_message_error_invalid_brainkey_point_len_chars[] = "Brainkey point length should be 65 bytes.";

static const vsc_str_t k_message_error_invalid_brainkey_point_len = {
    k_message_error_invalid_brainkey_point_len_chars,
    sizeof(k_message_error_invalid_brainkey_point_len_chars) - 1
};

static const char k_message_error_invalid_brainkey_key_name_len_chars[] = "Brainkey name is out of range.";

static const vsc_str_t k_message_error_invalid_brainkey_key_name_len = {
    k_message_error_invalid_brainkey_key_name_len_chars,
    sizeof(k_message_error_invalid_brainkey_key_name_len_chars) - 1
};

static const char k_message_error_brainkey_internal_chars[] = "Brainkey internal error.";

static const vsc_str_t k_message_error_brainkey_internal = {
    k_message_error_brainkey_internal_chars,
    sizeof(k_message_error_brainkey_internal_chars) - 1
};

static const char k_message_error_brainkey_invalid_point_chars[] = "Brainkey point is invalid.";

static const vsc_str_t k_message_error_brainkey_invalid_point = {
    k_message_error_brainkey_invalid_point_chars,
    sizeof(k_message_error_brainkey_invalid_point_chars) - 1
};

static const char k_message_error_invalid_brainkey_factor_buffer_len_chars[] = "Brainkey number buffer length capacity should be >= 32 byte.";

static const vsc_str_t k_message_error_invalid_brainkey_factor_buffer_len = {
    k_message_error_invalid_brainkey_factor_buffer_len_chars,
    sizeof(k_message_error_invalid_brainkey_factor_buffer_len_chars) - 1
};

static const char k_message_error_invalid_brainkey_point_buffer_len_chars[] = "Brainkey point buffer length capacity should be >= 32 byte.";

static const vsc_str_t k_message_error_invalid_brainkey_point_buffer_len = {
    k_message_error_invalid_brainkey_point_buffer_len_chars,
    sizeof(k_message_error_invalid_brainkey_point_buffer_len_chars) - 1
};

static const char k_message_error_invalid_brainkey_seed_buffer_len_chars[] = "Brainkey seed buffer length capacity should be >= 32 byte.";

static const vsc_str_t k_message_error_invalid_brainkey_seed_buffer_len = {
    k_message_error_invalid_brainkey_seed_buffer_len_chars,
    sizeof(k_message_error_invalid_brainkey_seed_buffer_len_chars) - 1
};

static const char k_message_error_invalid_identity_secret_chars[] = "Brainkey identity secret is invalid.";

static const vsc_str_t k_message_error_invalid_identity_secret = {
    k_message_error_invalid_identity_secret_chars,
    sizeof(k_message_error_invalid_identity_secret_chars) - 1
};

static const char k_message_error_invalid_kem_encapsulated_key_chars[] = "KEM encapsulated key is invalid or does not correspond to the private key.";

static const vsc_str_t k_message_error_invalid_kem_encapsulated_key = {
    k_message_error_invalid_kem_encapsulated_key_chars,
    sizeof(k_message_error_invalid_kem_encapsulated_key_chars) - 1
};

static const char k_message_error_invalid_padding_chars[] = "Invalid padding.";

static const vsc_str_t k_message_error_invalid_padding = {
    k_message_error_invalid_padding_chars,
    sizeof(k_message_error_invalid_padding_chars) - 1
};

static const char k_message_error_protobuf_chars[] = "Protobuf error.";

static const vsc_str_t k_message_error_protobuf = {
    k_message_error_protobuf_chars,
    sizeof(k_message_error_protobuf_chars) - 1
};

static const char k_message_error_session_id_doesnt_match_chars[] = "Session id doesnt match.";

static const vsc_str_t k_message_error_session_id_doesnt_match = {
    k_message_error_session_id_doesnt_match_chars,
    sizeof(k_message_error_session_id_doesnt_match_chars) - 1
};

static const char k_message_error_epoch_not_found_chars[] = "Epoch not found.";

static const vsc_str_t k_message_error_epoch_not_found = {
    k_message_error_epoch_not_found_chars,
    sizeof(k_message_error_epoch_not_found_chars) - 1
};

static const char k_message_error_wrong_key_type_chars[] = "Wrong key type.";

static const vsc_str_t k_message_error_wrong_key_type = {
    k_message_error_wrong_key_type_chars,
    sizeof(k_message_error_wrong_key_type_chars) - 1
};

static const char k_message_error_invalid_signature_chars[] = "Invalid signature.";

static const vsc_str_t k_message_error_invalid_signature = {
    k_message_error_invalid_signature_chars,
    sizeof(k_message_error_invalid_signature_chars) - 1
};

static const char k_message_error_ed25519_chars[] = "Ed25519 error.";

static const vsc_str_t k_message_error_ed25519 = {
    k_message_error_ed25519_chars,
    sizeof(k_message_error_ed25519_chars) - 1
};

static const char k_message_error_duplicate_epoch_chars[] = "Duplicate epoch.";

static const vsc_str_t k_message_error_duplicate_epoch = {
    k_message_error_duplicate_epoch_chars,
    sizeof(k_message_error_duplicate_epoch_chars) - 1
};

static const char k_message_error_plain_text_too_long_chars[] = "Plain text too long.";

static const vsc_str_t k_message_error_plain_text_too_long = {
    k_message_error_plain_text_too_long_chars,
    sizeof(k_message_error_plain_text_too_long_chars) - 1
};

//
//  Return a message string from the given status.
//
VSCF_PUBLIC vsc_str_t
vscf_error_message_from_status(vscf_status_t status) {

    switch(status) {
        case vscf_status_SUCCESS:
            return k_message_success;
        case vscf_status_ERROR_BAD_ARGUMENTS:
            return k_message_error_bad_arguments;
        case vscf_status_ERROR_UNINITIALIZED:
            return k_message_error_uninitialized;
        case vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR:
            return k_message_error_unhandled_thirdparty_error;
        case vscf_status_ERROR_SMALL_BUFFER:
            return k_message_error_small_buffer;
        case vscf_status_HEX_TO_BYTES_FAILED:
            return k_message_hex_to_bytes_failed;
        case vscf_status_ERROR_UNSUPPORTED_ALGORITHM:
            return k_message_error_unsupported_algorithm;
        case vscf_status_ERROR_AUTH_FAILED:
            return k_message_error_auth_failed;
        case vscf_status_ERROR_OUT_OF_DATA:
            return k_message_error_out_of_data;
        case vscf_status_ERROR_BAD_ASN1:
            return k_message_error_bad_asn1;
        case vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING:
            return k_message_error_asn1_lossy_type_narrowing;
        case vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY:
            return k_message_error_bad_pkcs1_public_key;
        case vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY:
            return k_message_error_bad_pkcs1_private_key;
        case vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY:
            return k_message_error_bad_pkcs8_public_key;
        case vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY:
            return k_message_error_bad_pkcs8_private_key;
        case vscf_status_ERROR_BAD_ENCRYPTED_DATA:
            return k_message_error_bad_encrypted_data;
        case vscf_status_ERROR_RANDOM_FAILED:
            return k_message_error_random_failed;
        case vscf_status_ERROR_KEY_GENERATION_FAILED:
            return k_message_error_key_generation_failed;
        case vscf_status_ERROR_ENTROPY_SOURCE_FAILED:
            return k_message_error_entropy_source_failed;
        case vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG:
            return k_message_error_rng_requested_data_too_big;
        case vscf_status_ERROR_BAD_BASE64:
            return k_message_error_bad_base64;
        case vscf_status_ERROR_BAD_PEM:
            return k_message_error_bad_pem;
        case vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED:
            return k_message_error_shared_key_exchange_failed;
        case vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY:
            return k_message_error_bad_ed25519_public_key;
        case vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY:
            return k_message_error_bad_ed25519_private_key;
        case vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY:
            return k_message_error_bad_curve25519_public_key;
        case vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY:
            return k_message_error_bad_curve25519_private_key;
        case vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY:
            return k_message_error_bad_sec1_public_key;
        case vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY:
            return k_message_error_bad_sec1_private_key;
        case vscf_status_ERROR_BAD_DER_PUBLIC_KEY:
            return k_message_error_bad_der_public_key;
        case vscf_status_ERROR_BAD_DER_PRIVATE_KEY:
            return k_message_error_bad_der_private_key;
        case vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM:
            return k_message_error_mismatch_public_key_and_algorithm;
        case vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM:
            return k_message_error_mismatch_private_key_and_algorithm;
        case vscf_status_ERROR_BAD_FALCON_PUBLIC_KEY:
            return k_message_error_bad_falcon_public_key;
        case vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY:
            return k_message_error_bad_falcon_private_key;
        case vscf_status_ERROR_ROUND5:
            return k_message_error_round5;
        case vscf_status_ERROR_BAD_ROUND5_PUBLIC_KEY:
            return k_message_error_bad_round5_public_key;
        case vscf_status_ERROR_BAD_ROUND5_PRIVATE_KEY:
            return k_message_error_bad_round5_private_key;
        case vscf_status_ERROR_BAD_COMPOUND_PUBLIC_KEY:
            return k_message_error_bad_compound_public_key;
        case vscf_status_ERROR_BAD_COMPOUND_PRIVATE_KEY:
            return k_message_error_bad_compound_private_key;
        case vscf_status_ERROR_BAD_HYBRID_PUBLIC_KEY:
            return k_message_error_bad_hybrid_public_key;
        case vscf_status_ERROR_BAD_HYBRID_PRIVATE_KEY:
            return k_message_error_bad_hybrid_private_key;
        case vscf_status_ERROR_BAD_ASN1_ALGORITHM:
            return k_message_error_bad_asn1_algorithm;
        case vscf_status_ERROR_BAD_ASN1_ALGORITHM_ECC:
            return k_message_error_bad_asn1_algorithm_ecc;
        case vscf_status_ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY:
            return k_message_error_bad_asn1_algorithm_compound_key;
        case vscf_status_ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY:
            return k_message_error_bad_asn1_algorithm_hybrid_key;
        case vscf_status_ERROR_NO_MESSAGE_INFO:
            return k_message_error_no_message_info;
        case vscf_status_ERROR_BAD_MESSAGE_INFO:
            return k_message_error_bad_message_info;
        case vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
            return k_message_error_key_recipient_is_not_found;
        case vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
            return k_message_error_key_recipient_private_key_is_wrong;
        case vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
            return k_message_error_password_recipient_password_is_wrong;
        case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
            return k_message_error_message_info_custom_param_not_found;
        case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
            return k_message_error_message_info_custom_param_type_mismatch;
        case vscf_status_ERROR_BAD_SIGNATURE:
            return k_message_error_bad_signature;
        case vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER:
            return k_message_error_bad_message_info_footer;
        case vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
            return k_message_error_invalid_brainkey_password_len;
        case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN:
            return k_message_error_invalid_brainkey_factor_len;
        case vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN:
            return k_message_error_invalid_brainkey_point_len;
        case vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
            return k_message_error_invalid_brainkey_key_name_len;
        case vscf_status_ERROR_BRAINKEY_INTERNAL:
            return k_message_error_brainkey_internal;
        case vscf_status_ERROR_BRAINKEY_INVALID_POINT:
            return k_message_error_brainkey_invalid_point;
        case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
            return k_message_error_invalid_brainkey_factor_buffer_len;
        case vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
            return k_message_error_invalid_brainkey_point_buffer_len;
        case vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
            return k_message_error_invalid_brainkey_seed_buffer_len;
        case vscf_status_ERROR_INVALID_IDENTITY_SECRET:
            return k_message_error_invalid_identity_secret;
        case vscf_status_ERROR_INVALID_KEM_ENCAPSULATED_KEY:
            return k_message_error_invalid_kem_encapsulated_key;
        case vscf_status_ERROR_INVALID_PADDING:
            return k_message_error_invalid_padding;
        case vscf_status_ERROR_PROTOBUF:
            return k_message_error_protobuf;
        case vscf_status_ERROR_SESSION_ID_DOESNT_MATCH:
            return k_message_error_session_id_doesnt_match;
        case vscf_status_ERROR_EPOCH_NOT_FOUND:
            return k_message_error_epoch_not_found;
        case vscf_status_ERROR_WRONG_KEY_TYPE:
            return k_message_error_wrong_key_type;
        case vscf_status_ERROR_INVALID_SIGNATURE:
            return k_message_error_invalid_signature;
        case vscf_status_ERROR_ED25519:
            return k_message_error_ed25519;
        case vscf_status_ERROR_DUPLICATE_EPOCH:
            return k_message_error_duplicate_epoch;
        case vscf_status_ERROR_PLAIN_TEXT_TOO_LONG:
            return k_message_error_plain_text_too_long;
        default:
            return k_message_unknown_error;
    }
}

//
//  Return a message string from the given status.
//
VSCF_PUBLIC vsc_str_t
vscf_error_message_from_error(const vscf_error_t *error) {

    VSCF_ASSERT_PTR(error);
    return vscf_error_message_from_status(error->status);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
