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

#include "vssq_error_message.h"
#include "vssq_memory.h"
#include "vssq_assert.h"

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

static const char k_message_internal_error_chars[] = "Met internal inconsistency.";

static const vsc_str_t k_message_internal_error = {
    k_message_internal_error_chars,
    sizeof(k_message_internal_error_chars) - 1
};

static const char k_message_rng_failed_chars[] = "Failed to initialize RNG.";

static const vsc_str_t k_message_rng_failed = {
    k_message_rng_failed_chars,
    sizeof(k_message_rng_failed_chars) - 1
};

static const char k_message_not_found_chars[] = "Generic error for any find operation.";

static const vsc_str_t k_message_not_found = {
    k_message_not_found_chars,
    sizeof(k_message_not_found_chars) - 1
};

static const char k_message_http_send_failed_chars[] = "Failed to send HTTP request.";

static const vsc_str_t k_message_http_send_failed = {
    k_message_http_send_failed_chars,
    sizeof(k_message_http_send_failed_chars) - 1
};

static const char k_message_parse_ejabberd_jwt_failed_chars[] = "Failed to parse Ejabberd JWT.";

static const vsc_str_t k_message_parse_ejabberd_jwt_failed = {
    k_message_parse_ejabberd_jwt_failed_chars,
    sizeof(k_message_parse_ejabberd_jwt_failed_chars) - 1
};

static const char k_message_generate_identity_failed_chars[] = "Failed to generate identity.";

static const vsc_str_t k_message_generate_identity_failed = {
    k_message_generate_identity_failed_chars,
    sizeof(k_message_generate_identity_failed_chars) - 1
};

static const char k_message_generate_private_key_failed_chars[] = "Failed to generate private key.";

static const vsc_str_t k_message_generate_private_key_failed = {
    k_message_generate_private_key_failed_chars,
    sizeof(k_message_generate_private_key_failed_chars) - 1
};

static const char k_message_import_private_key_failed_chars[] = "Failed to import private key.";

static const vsc_str_t k_message_import_private_key_failed = {
    k_message_import_private_key_failed_chars,
    sizeof(k_message_import_private_key_failed_chars) - 1
};

static const char k_message_export_private_key_failed_chars[] = "Failed to export private key.";

static const vsc_str_t k_message_export_private_key_failed = {
    k_message_export_private_key_failed_chars,
    sizeof(k_message_export_private_key_failed_chars) - 1
};

static const char k_message_calculate_key_id_failed_chars[] = "Failed to calculate key id.";

static const vsc_str_t k_message_calculate_key_id_failed = {
    k_message_calculate_key_id_failed_chars,
    sizeof(k_message_calculate_key_id_failed_chars) - 1
};

static const char k_message_create_card_manager_failed_chars[] = "Failed to create card manager.";

static const vsc_str_t k_message_create_card_manager_failed = {
    k_message_create_card_manager_failed_chars,
    sizeof(k_message_create_card_manager_failed_chars) - 1
};

static const char k_message_generate_card_failed_chars[] = "Failed to generate card.";

static const vsc_str_t k_message_generate_card_failed = {
    k_message_generate_card_failed_chars,
    sizeof(k_message_generate_card_failed_chars) - 1
};

static const char k_message_generate_auth_header_failed_chars[] = "Failed to generate HTTP authentication header.";

static const vsc_str_t k_message_generate_auth_header_failed = {
    k_message_generate_auth_header_failed_chars,
    sizeof(k_message_generate_auth_header_failed_chars) - 1
};

static const char k_message_register_card_failed_request_failed_chars[] = "Failed to register card because send operation failed.";

static const vsc_str_t k_message_register_card_failed_request_failed = {
    k_message_register_card_failed_request_failed_chars,
    sizeof(k_message_register_card_failed_request_failed_chars) - 1
};

static const char k_message_register_card_failed_invalid_response_chars[] = "Failed to register card because of invalid response.";

static const vsc_str_t k_message_register_card_failed_invalid_response = {
    k_message_register_card_failed_invalid_response_chars,
    sizeof(k_message_register_card_failed_invalid_response_chars) - 1
};

static const char k_message_register_card_failed_response_with_error_chars[] = "Failed to register card because response with error was returned.";

static const vsc_str_t k_message_register_card_failed_response_with_error = {
    k_message_register_card_failed_response_with_error_chars,
    sizeof(k_message_register_card_failed_response_with_error_chars) - 1
};

static const char k_message_register_card_failed_parse_failed_chars[] = "Failed to register card because parsing raw card failed.";

static const vsc_str_t k_message_register_card_failed_parse_failed = {
    k_message_register_card_failed_parse_failed_chars,
    sizeof(k_message_register_card_failed_parse_failed_chars) - 1
};

static const char k_message_register_card_failed_import_failed_chars[] = "Failed to register card because import raw card failed.";

static const vsc_str_t k_message_register_card_failed_import_failed = {
    k_message_register_card_failed_import_failed_chars,
    sizeof(k_message_register_card_failed_import_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_crypto_failed_chars[] = "Failed to generate brain key because of crypto fail.";

static const vsc_str_t k_message_generate_brainkey_failed_crypto_failed = {
    k_message_generate_brainkey_failed_crypto_failed_chars,
    sizeof(k_message_generate_brainkey_failed_crypto_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_rng_failed_chars[] = "Failed to generate brain key because of RNG fail.";

static const vsc_str_t k_message_generate_brainkey_failed_rng_failed = {
    k_message_generate_brainkey_failed_rng_failed_chars,
    sizeof(k_message_generate_brainkey_failed_rng_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_blind_failed_chars[] = "Failed to generate brain key because of blind fail.";

static const vsc_str_t k_message_generate_brainkey_failed_blind_failed = {
    k_message_generate_brainkey_failed_blind_failed_chars,
    sizeof(k_message_generate_brainkey_failed_blind_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_deblind_failed_chars[] = "Failed to generate brain key because of deblind fail.";

static const vsc_str_t k_message_generate_brainkey_failed_deblind_failed = {
    k_message_generate_brainkey_failed_deblind_failed_chars,
    sizeof(k_message_generate_brainkey_failed_deblind_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_hardened_point_request_failed_chars[] = "Failed to generate brain key because requesting hardened point from the service failed.";

static const vsc_str_t k_message_generate_brainkey_failed_hardened_point_request_failed = {
    k_message_generate_brainkey_failed_hardened_point_request_failed_chars,
    sizeof(k_message_generate_brainkey_failed_hardened_point_request_failed_chars) - 1
};

static const char k_message_generate_brainkey_failed_hardened_point_response_with_error_chars[] = "Failed to generate brain key because hardened point response was returned with error.";

static const vsc_str_t k_message_generate_brainkey_failed_hardened_point_response_with_error = {
    k_message_generate_brainkey_failed_hardened_point_response_with_error_chars,
    sizeof(k_message_generate_brainkey_failed_hardened_point_response_with_error_chars) - 1
};

static const char k_message_generate_brainkey_failed_hardened_point_parse_failed_chars[] = "Failed to generate brain key because parsing hardened point response failed.";

static const vsc_str_t k_message_generate_brainkey_failed_hardened_point_parse_failed = {
    k_message_generate_brainkey_failed_hardened_point_parse_failed_chars,
    sizeof(k_message_generate_brainkey_failed_hardened_point_parse_failed_chars) - 1
};

static const char k_message_keyknox_failed_request_failed_chars[] = "Failed to process Keyknox entry because send operation failed.";

static const vsc_str_t k_message_keyknox_failed_request_failed = {
    k_message_keyknox_failed_request_failed_chars,
    sizeof(k_message_keyknox_failed_request_failed_chars) - 1
};

static const char k_message_keyknox_failed_response_with_error_chars[] = "Failed to process Keyknox entry because response with error was returned.";

static const vsc_str_t k_message_keyknox_failed_response_with_error = {
    k_message_keyknox_failed_response_with_error_chars,
    sizeof(k_message_keyknox_failed_response_with_error_chars) - 1
};

static const char k_message_keyknox_failed_parse_response_failed_chars[] = "Failed to process Keyknox entry because response parsing failed.";

static const vsc_str_t k_message_keyknox_failed_parse_response_failed = {
    k_message_keyknox_failed_parse_response_failed_chars,
    sizeof(k_message_keyknox_failed_parse_response_failed_chars) - 1
};

static const char k_message_keyknox_pack_entry_failed_export_private_key_failed_chars[] = "Failed to pack Keyknox entry because export private key failed.";

static const vsc_str_t k_message_keyknox_pack_entry_failed_export_private_key_failed = {
    k_message_keyknox_pack_entry_failed_export_private_key_failed_chars,
    sizeof(k_message_keyknox_pack_entry_failed_export_private_key_failed_chars) - 1
};

static const char k_message_keyknox_pack_entry_failed_encrypt_failed_chars[] = "Failed to pack Keyknox entry because encrypt operation failed.";

static const vsc_str_t k_message_keyknox_pack_entry_failed_encrypt_failed = {
    k_message_keyknox_pack_entry_failed_encrypt_failed_chars,
    sizeof(k_message_keyknox_pack_entry_failed_encrypt_failed_chars) - 1
};

static const char k_message_keyknox_unpack_entry_failed_decrypt_failed_chars[] = "Failed to unpack Keyknox entry because decrypt operation failed.";

static const vsc_str_t k_message_keyknox_unpack_entry_failed_decrypt_failed = {
    k_message_keyknox_unpack_entry_failed_decrypt_failed_chars,
    sizeof(k_message_keyknox_unpack_entry_failed_decrypt_failed_chars) - 1
};

static const char k_message_keyknox_unpack_entry_failed_verify_signature_failed_chars[] = "Failed to unpack Keyknox entry because verifying signature failed.";

static const vsc_str_t k_message_keyknox_unpack_entry_failed_verify_signature_failed = {
    k_message_keyknox_unpack_entry_failed_verify_signature_failed_chars,
    sizeof(k_message_keyknox_unpack_entry_failed_verify_signature_failed_chars) - 1
};

static const char k_message_keyknox_unpack_entry_failed_parse_failed_chars[] = "Failed to unpack Keyknox entry because parse operation failed.";

static const vsc_str_t k_message_keyknox_unpack_entry_failed_parse_failed = {
    k_message_keyknox_unpack_entry_failed_parse_failed_chars,
    sizeof(k_message_keyknox_unpack_entry_failed_parse_failed_chars) - 1
};

static const char k_message_keyknox_unpack_entry_failed_import_private_key_failed_chars[] = "Failed to unpack Keyknox entry because import private key failed.";

static const vsc_str_t k_message_keyknox_unpack_entry_failed_import_private_key_failed = {
    k_message_keyknox_unpack_entry_failed_import_private_key_failed_chars,
    sizeof(k_message_keyknox_unpack_entry_failed_import_private_key_failed_chars) - 1
};

static const char k_message_refresh_jwt_failed_request_failed_chars[] = "Failed to refresh JWT because send operation failed.";

static const vsc_str_t k_message_refresh_jwt_failed_request_failed = {
    k_message_refresh_jwt_failed_request_failed_chars,
    sizeof(k_message_refresh_jwt_failed_request_failed_chars) - 1
};

static const char k_message_refresh_jwt_failed_response_with_error_chars[] = "Failed to refresh JWT because response with error was returned.";

static const vsc_str_t k_message_refresh_jwt_failed_response_with_error = {
    k_message_refresh_jwt_failed_response_with_error_chars,
    sizeof(k_message_refresh_jwt_failed_response_with_error_chars) - 1
};

static const char k_message_refresh_jwt_failed_parse_response_failed_chars[] = "Failed to refresh JWT because response parsing failed.";

static const vsc_str_t k_message_refresh_jwt_failed_parse_response_failed = {
    k_message_refresh_jwt_failed_parse_response_failed_chars,
    sizeof(k_message_refresh_jwt_failed_parse_response_failed_chars) - 1
};

static const char k_message_refresh_jwt_failed_parse_failed_chars[] = "Failed to refresh JWT because JWT parsing failed.";

static const vsc_str_t k_message_refresh_jwt_failed_parse_failed = {
    k_message_refresh_jwt_failed_parse_failed_chars,
    sizeof(k_message_refresh_jwt_failed_parse_failed_chars) - 1
};

static const char k_message_reset_password_failed_request_failed_chars[] = "Failed to reset password because send operation failed.";

static const vsc_str_t k_message_reset_password_failed_request_failed = {
    k_message_reset_password_failed_request_failed_chars,
    sizeof(k_message_reset_password_failed_request_failed_chars) - 1
};

static const char k_message_reset_password_failed_response_with_error_chars[] = "Failed to reset password because response with error was returned.";

static const vsc_str_t k_message_reset_password_failed_response_with_error = {
    k_message_reset_password_failed_response_with_error_chars,
    sizeof(k_message_reset_password_failed_response_with_error_chars) - 1
};

static const char k_message_search_card_failed_init_failed_chars[] = "Failed to search card because a card manager initialization failed.";

static const vsc_str_t k_message_search_card_failed_init_failed = {
    k_message_search_card_failed_init_failed_chars,
    sizeof(k_message_search_card_failed_init_failed_chars) - 1
};

static const char k_message_search_card_failed_request_failed_chars[] = "Failed to search card because send operation failed.";

static const vsc_str_t k_message_search_card_failed_request_failed = {
    k_message_search_card_failed_request_failed_chars,
    sizeof(k_message_search_card_failed_request_failed_chars) - 1
};

static const char k_message_search_card_failed_response_with_error_chars[] = "Failed to search card because response with error was returned.";

static const vsc_str_t k_message_search_card_failed_response_with_error = {
    k_message_search_card_failed_response_with_error_chars,
    sizeof(k_message_search_card_failed_response_with_error_chars) - 1
};

static const char k_message_search_card_failed_required_not_found_chars[] = "Failed to search card because required card was not found.";

static const vsc_str_t k_message_search_card_failed_required_not_found = {
    k_message_search_card_failed_required_not_found_chars,
    sizeof(k_message_search_card_failed_required_not_found_chars) - 1
};

static const char k_message_search_card_failed_multiple_found_chars[] = "Failed to search card because found more then one active card.";

static const vsc_str_t k_message_search_card_failed_multiple_found = {
    k_message_search_card_failed_multiple_found_chars,
    sizeof(k_message_search_card_failed_multiple_found_chars) - 1
};

static const char k_message_search_card_failed_parse_failed_chars[] = "Failed to search card because parsing raw card failed.";

static const vsc_str_t k_message_search_card_failed_parse_failed = {
    k_message_search_card_failed_parse_failed_chars,
    sizeof(k_message_search_card_failed_parse_failed_chars) - 1
};

static const char k_message_search_card_failed_import_failed_chars[] = "Failed to search card because import raw card failed.";

static const vsc_str_t k_message_search_card_failed_import_failed = {
    k_message_search_card_failed_import_failed_chars,
    sizeof(k_message_search_card_failed_import_failed_chars) - 1
};

static const char k_message_search_card_failed_required_is_outdated_chars[] = "Failed to search card because required card is outdated.";

static const vsc_str_t k_message_search_card_failed_required_is_outdated = {
    k_message_search_card_failed_required_is_outdated_chars,
    sizeof(k_message_search_card_failed_required_is_outdated_chars) - 1
};

static const char k_message_export_creds_failed_init_crypto_failed_chars[] = "Failed to export credentials because initializing crypto module failed.";

static const vsc_str_t k_message_export_creds_failed_init_crypto_failed = {
    k_message_export_creds_failed_init_crypto_failed_chars,
    sizeof(k_message_export_creds_failed_init_crypto_failed_chars) - 1
};

static const char k_message_export_creds_failed_export_private_key_failed_chars[] = "Failed to export credentials because exporting private key failed.";

static const vsc_str_t k_message_export_creds_failed_export_private_key_failed = {
    k_message_export_creds_failed_export_private_key_failed_chars,
    sizeof(k_message_export_creds_failed_export_private_key_failed_chars) - 1
};

static const char k_message_import_creds_failed_init_crypto_failed_chars[] = "Failed to import credentials because initializing crypto module failed.";

static const vsc_str_t k_message_import_creds_failed_init_crypto_failed = {
    k_message_import_creds_failed_init_crypto_failed_chars,
    sizeof(k_message_import_creds_failed_init_crypto_failed_chars) - 1
};

static const char k_message_import_creds_failed_parse_failed_chars[] = "Failed to import credentials because parsing JSON failed.";

static const vsc_str_t k_message_import_creds_failed_parse_failed = {
    k_message_import_creds_failed_parse_failed_chars,
    sizeof(k_message_import_creds_failed_parse_failed_chars) - 1
};

static const char k_message_import_creds_failed_import_private_key_failed_chars[] = "Failed to import credentials because importing private key failed.";

static const vsc_str_t k_message_import_creds_failed_import_private_key_failed = {
    k_message_import_creds_failed_import_private_key_failed_chars,
    sizeof(k_message_import_creds_failed_import_private_key_failed_chars) - 1
};

static const char k_message_contact_validation_failed_username_too_long_chars[] = "Username validation failed because it's length exceeds the allowed maximum (20).";

static const vsc_str_t k_message_contact_validation_failed_username_too_long = {
    k_message_contact_validation_failed_username_too_long_chars,
    sizeof(k_message_contact_validation_failed_username_too_long_chars) - 1
};

static const char k_message_contact_validation_failed_username_bad_chars_chars[] = "Username validation failed because it contains invalid characters.";

static const vsc_str_t k_message_contact_validation_failed_username_bad_chars = {
    k_message_contact_validation_failed_username_bad_chars_chars,
    sizeof(k_message_contact_validation_failed_username_bad_chars_chars) - 1
};

static const char k_message_contact_validation_failed_phone_number_bad_format_chars[] = "Phone number validation failed because it does not conform to E.164 standard.";

static const vsc_str_t k_message_contact_validation_failed_phone_number_bad_format = {
    k_message_contact_validation_failed_phone_number_bad_format_chars,
    sizeof(k_message_contact_validation_failed_phone_number_bad_format_chars) - 1
};

static const char k_message_contact_validation_failed_email_bad_format_chars[] = "Email validation failed because it has invalid format.";

static const vsc_str_t k_message_contact_validation_failed_email_bad_format = {
    k_message_contact_validation_failed_email_bad_format_chars,
    sizeof(k_message_contact_validation_failed_email_bad_format_chars) - 1
};

static const char k_message_modify_group_failed_permission_violation_chars[] = "The current user can not modify the group - permission violation.";

static const vsc_str_t k_message_modify_group_failed_permission_violation = {
    k_message_modify_group_failed_permission_violation_chars,
    sizeof(k_message_modify_group_failed_permission_violation_chars) - 1
};

static const char k_message_access_group_failed_permission_violation_chars[] = "The current user can not access the group - permission violation.";

static const vsc_str_t k_message_access_group_failed_permission_violation = {
    k_message_access_group_failed_permission_violation_chars,
    sizeof(k_message_access_group_failed_permission_violation_chars) - 1
};

static const char k_message_create_group_failed_crypto_failed_chars[] = "Failed to create group because underlying crypto module failed.";

static const vsc_str_t k_message_create_group_failed_crypto_failed = {
    k_message_create_group_failed_crypto_failed_chars,
    sizeof(k_message_create_group_failed_crypto_failed_chars) - 1
};

static const char k_message_import_group_epoch_failed_parse_failed_chars[] = "Failed to import group epoch because parsing JSON failed.";

static const vsc_str_t k_message_import_group_epoch_failed_parse_failed = {
    k_message_import_group_epoch_failed_parse_failed_chars,
    sizeof(k_message_import_group_epoch_failed_parse_failed_chars) - 1
};

static const char k_message_process_group_message_failed_session_id_doesnt_match_chars[] = "Failed to process group message because session id doesn't match.";

static const vsc_str_t k_message_process_group_message_failed_session_id_doesnt_match = {
    k_message_process_group_message_failed_session_id_doesnt_match_chars,
    sizeof(k_message_process_group_message_failed_session_id_doesnt_match_chars) - 1
};

static const char k_message_process_group_message_failed_epoch_not_found_chars[] = "Failed to process group message because epoch not found.";

static const vsc_str_t k_message_process_group_message_failed_epoch_not_found = {
    k_message_process_group_message_failed_epoch_not_found_chars,
    sizeof(k_message_process_group_message_failed_epoch_not_found_chars) - 1
};

static const char k_message_process_group_message_failed_wrong_key_type_chars[] = "Failed to process group message because wrong key type.";

static const vsc_str_t k_message_process_group_message_failed_wrong_key_type = {
    k_message_process_group_message_failed_wrong_key_type_chars,
    sizeof(k_message_process_group_message_failed_wrong_key_type_chars) - 1
};

static const char k_message_process_group_message_failed_invalid_signature_chars[] = "Failed to process group message because of invalid signature.";

static const vsc_str_t k_message_process_group_message_failed_invalid_signature = {
    k_message_process_group_message_failed_invalid_signature_chars,
    sizeof(k_message_process_group_message_failed_invalid_signature_chars) - 1
};

static const char k_message_process_group_message_failed_ed25519_failed_chars[] = "Failed to process group message because ed25519 failed.";

static const vsc_str_t k_message_process_group_message_failed_ed25519_failed = {
    k_message_process_group_message_failed_ed25519_failed_chars,
    sizeof(k_message_process_group_message_failed_ed25519_failed_chars) - 1
};

static const char k_message_process_group_message_failed_duplicate_epoch_chars[] = "Failed to process group message because of duplicated epoch.";

static const vsc_str_t k_message_process_group_message_failed_duplicate_epoch = {
    k_message_process_group_message_failed_duplicate_epoch_chars,
    sizeof(k_message_process_group_message_failed_duplicate_epoch_chars) - 1
};

static const char k_message_process_group_message_failed_plain_text_too_long_chars[] = "Failed to process group message because plain text too long.";

static const vsc_str_t k_message_process_group_message_failed_plain_text_too_long = {
    k_message_process_group_message_failed_plain_text_too_long_chars,
    sizeof(k_message_process_group_message_failed_plain_text_too_long_chars) - 1
};

static const char k_message_process_group_message_failed_crypto_failed_chars[] = "Failed to process group message because underlying crypto module failed.";

static const vsc_str_t k_message_process_group_message_failed_crypto_failed = {
    k_message_process_group_message_failed_crypto_failed_chars,
    sizeof(k_message_process_group_message_failed_crypto_failed_chars) - 1
};

static const char k_message_decrypt_regular_message_failed_invalid_encrypted_message_chars[] = "Failed to decrypt regular message because of invalid encrypted message.";

static const vsc_str_t k_message_decrypt_regular_message_failed_invalid_encrypted_message = {
    k_message_decrypt_regular_message_failed_invalid_encrypted_message_chars,
    sizeof(k_message_decrypt_regular_message_failed_invalid_encrypted_message_chars) - 1
};

static const char k_message_decrypt_regular_message_failed_wrong_private_key_chars[] = "Failed to decrypt regular message because a private key can not decrypt.";

static const vsc_str_t k_message_decrypt_regular_message_failed_wrong_private_key = {
    k_message_decrypt_regular_message_failed_wrong_private_key_chars,
    sizeof(k_message_decrypt_regular_message_failed_wrong_private_key_chars) - 1
};

static const char k_message_decrypt_regular_message_failed_recipient_not_found_chars[] = "Failed to decrypt regular message because recipient was not found.";

static const vsc_str_t k_message_decrypt_regular_message_failed_recipient_not_found = {
    k_message_decrypt_regular_message_failed_recipient_not_found_chars,
    sizeof(k_message_decrypt_regular_message_failed_recipient_not_found_chars) - 1
};

static const char k_message_decrypt_regular_message_failed_verify_signature_chars[] = "Failed to decrypt regular message because failed to verify signature.";

static const vsc_str_t k_message_decrypt_regular_message_failed_verify_signature = {
    k_message_decrypt_regular_message_failed_verify_signature_chars,
    sizeof(k_message_decrypt_regular_message_failed_verify_signature_chars) - 1
};

static const char k_message_decrypt_regular_message_failed_crypto_failed_chars[] = "Failed to decrypt regular message because underlying crypto module failed.";

static const vsc_str_t k_message_decrypt_regular_message_failed_crypto_failed = {
    k_message_decrypt_regular_message_failed_crypto_failed_chars,
    sizeof(k_message_decrypt_regular_message_failed_crypto_failed_chars) - 1
};

static const char k_message_encrypt_regular_message_failed_crypto_failed_chars[] = "Failed to encrypt regular message because underlying crypto module failed.";

static const vsc_str_t k_message_encrypt_regular_message_failed_crypto_failed = {
    k_message_encrypt_regular_message_failed_crypto_failed_chars,
    sizeof(k_message_encrypt_regular_message_failed_crypto_failed_chars) - 1
};

static const char k_message_contacts_failed_send_request_failed_chars[] = "Failed to perform contacts operation because send operation failed.";

static const vsc_str_t k_message_contacts_failed_send_request_failed = {
    k_message_contacts_failed_send_request_failed_chars,
    sizeof(k_message_contacts_failed_send_request_failed_chars) - 1
};

static const char k_message_contacts_failed_response_with_error_chars[] = "Failed to perform contacts operation because response with error was returned.";

static const vsc_str_t k_message_contacts_failed_response_with_error = {
    k_message_contacts_failed_response_with_error_chars,
    sizeof(k_message_contacts_failed_response_with_error_chars) - 1
};

static const char k_message_contacts_failed_parse_response_failed_chars[] = "Failed to perform contacts operation because response parsing failed.";

static const vsc_str_t k_message_contacts_failed_parse_response_failed = {
    k_message_contacts_failed_parse_response_failed_chars,
    sizeof(k_message_contacts_failed_parse_response_failed_chars) - 1
};

static const char k_message_cloud_fs_failed_send_request_failed_chars[] = "Communicate with Cloud FS failed because send request failed.";

static const vsc_str_t k_message_cloud_fs_failed_send_request_failed = {
    k_message_cloud_fs_failed_send_request_failed_chars,
    sizeof(k_message_cloud_fs_failed_send_request_failed_chars) - 1
};

static const char k_message_cloud_fs_failed_response_with_error_chars[] = "Communicate with Cloud FS failed because response with error was returned.";

static const vsc_str_t k_message_cloud_fs_failed_response_with_error = {
    k_message_cloud_fs_failed_response_with_error_chars,
    sizeof(k_message_cloud_fs_failed_response_with_error_chars) - 1
};

static const char k_message_cloud_fs_failed_unexpected_content_type_chars[] = "Communicate with Cloud FS failed because met unexpected content type.";

static const vsc_str_t k_message_cloud_fs_failed_unexpected_content_type = {
    k_message_cloud_fs_failed_unexpected_content_type_chars,
    sizeof(k_message_cloud_fs_failed_unexpected_content_type_chars) - 1
};

static const char k_message_cloud_fs_failed_parse_response_failed_chars[] = "Communicate with Cloud FS failed because failed to parse response body.";

static const vsc_str_t k_message_cloud_fs_failed_parse_response_failed = {
    k_message_cloud_fs_failed_parse_response_failed_chars,
    sizeof(k_message_cloud_fs_failed_parse_response_failed_chars) - 1
};

//
//  Return a message string from the given status.
//
VSSQ_PUBLIC vsc_str_t
vssq_error_message_from_status(vssq_status_t status) {

    switch(status) {
        case vssq_status_SUCCESS:
            return k_message_success;
        case vssq_status_INTERNAL_ERROR:
            return k_message_internal_error;
        case vssq_status_RNG_FAILED:
            return k_message_rng_failed;
        case vssq_status_NOT_FOUND:
            return k_message_not_found;
        case vssq_status_HTTP_SEND_FAILED:
            return k_message_http_send_failed;
        case vssq_status_PARSE_EJABBERD_JWT_FAILED:
            return k_message_parse_ejabberd_jwt_failed;
        case vssq_status_GENERATE_IDENTITY_FAILED:
            return k_message_generate_identity_failed;
        case vssq_status_GENERATE_PRIVATE_KEY_FAILED:
            return k_message_generate_private_key_failed;
        case vssq_status_IMPORT_PRIVATE_KEY_FAILED:
            return k_message_import_private_key_failed;
        case vssq_status_EXPORT_PRIVATE_KEY_FAILED:
            return k_message_export_private_key_failed;
        case vssq_status_CALCULATE_KEY_ID_FAILED:
            return k_message_calculate_key_id_failed;
        case vssq_status_CREATE_CARD_MANAGER_FAILED:
            return k_message_create_card_manager_failed;
        case vssq_status_GENERATE_CARD_FAILED:
            return k_message_generate_card_failed;
        case vssq_status_GENERATE_AUTH_HEADER_FAILED:
            return k_message_generate_auth_header_failed;
        case vssq_status_REGISTER_CARD_FAILED_REQUEST_FAILED:
            return k_message_register_card_failed_request_failed;
        case vssq_status_REGISTER_CARD_FAILED_INVALID_RESPONSE:
            return k_message_register_card_failed_invalid_response;
        case vssq_status_REGISTER_CARD_FAILED_RESPONSE_WITH_ERROR:
            return k_message_register_card_failed_response_with_error;
        case vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED:
            return k_message_register_card_failed_parse_failed;
        case vssq_status_REGISTER_CARD_FAILED_IMPORT_FAILED:
            return k_message_register_card_failed_import_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_CRYPTO_FAILED:
            return k_message_generate_brainkey_failed_crypto_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_RNG_FAILED:
            return k_message_generate_brainkey_failed_rng_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_BLIND_FAILED:
            return k_message_generate_brainkey_failed_blind_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_DEBLIND_FAILED:
            return k_message_generate_brainkey_failed_deblind_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_REQUEST_FAILED:
            return k_message_generate_brainkey_failed_hardened_point_request_failed;
        case vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_RESPONSE_WITH_ERROR:
            return k_message_generate_brainkey_failed_hardened_point_response_with_error;
        case vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_PARSE_FAILED:
            return k_message_generate_brainkey_failed_hardened_point_parse_failed;
        case vssq_status_KEYKNOX_FAILED_REQUEST_FAILED:
            return k_message_keyknox_failed_request_failed;
        case vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR:
            return k_message_keyknox_failed_response_with_error;
        case vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED:
            return k_message_keyknox_failed_parse_response_failed;
        case vssq_status_KEYKNOX_PACK_ENTRY_FAILED_EXPORT_PRIVATE_KEY_FAILED:
            return k_message_keyknox_pack_entry_failed_export_private_key_failed;
        case vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED:
            return k_message_keyknox_pack_entry_failed_encrypt_failed;
        case vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED:
            return k_message_keyknox_unpack_entry_failed_decrypt_failed;
        case vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED:
            return k_message_keyknox_unpack_entry_failed_verify_signature_failed;
        case vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED:
            return k_message_keyknox_unpack_entry_failed_parse_failed;
        case vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_IMPORT_PRIVATE_KEY_FAILED:
            return k_message_keyknox_unpack_entry_failed_import_private_key_failed;
        case vssq_status_REFRESH_JWT_FAILED_REQUEST_FAILED:
            return k_message_refresh_jwt_failed_request_failed;
        case vssq_status_REFRESH_JWT_FAILED_RESPONSE_WITH_ERROR:
            return k_message_refresh_jwt_failed_response_with_error;
        case vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED:
            return k_message_refresh_jwt_failed_parse_response_failed;
        case vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED:
            return k_message_refresh_jwt_failed_parse_failed;
        case vssq_status_RESET_PASSWORD_FAILED_REQUEST_FAILED:
            return k_message_reset_password_failed_request_failed;
        case vssq_status_RESET_PASSWORD_FAILED_RESPONSE_WITH_ERROR:
            return k_message_reset_password_failed_response_with_error;
        case vssq_status_SEARCH_CARD_FAILED_INIT_FAILED:
            return k_message_search_card_failed_init_failed;
        case vssq_status_SEARCH_CARD_FAILED_REQUEST_FAILED:
            return k_message_search_card_failed_request_failed;
        case vssq_status_SEARCH_CARD_FAILED_RESPONSE_WITH_ERROR:
            return k_message_search_card_failed_response_with_error;
        case vssq_status_SEARCH_CARD_FAILED_REQUIRED_NOT_FOUND:
            return k_message_search_card_failed_required_not_found;
        case vssq_status_SEARCH_CARD_FAILED_MULTIPLE_FOUND:
            return k_message_search_card_failed_multiple_found;
        case vssq_status_SEARCH_CARD_FAILED_PARSE_FAILED:
            return k_message_search_card_failed_parse_failed;
        case vssq_status_SEARCH_CARD_FAILED_IMPORT_FAILED:
            return k_message_search_card_failed_import_failed;
        case vssq_status_SEARCH_CARD_FAILED_REQUIRED_IS_OUTDATED:
            return k_message_search_card_failed_required_is_outdated;
        case vssq_status_EXPORT_CREDS_FAILED_INIT_CRYPTO_FAILED:
            return k_message_export_creds_failed_init_crypto_failed;
        case vssq_status_EXPORT_CREDS_FAILED_EXPORT_PRIVATE_KEY_FAILED:
            return k_message_export_creds_failed_export_private_key_failed;
        case vssq_status_IMPORT_CREDS_FAILED_INIT_CRYPTO_FAILED:
            return k_message_import_creds_failed_init_crypto_failed;
        case vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED:
            return k_message_import_creds_failed_parse_failed;
        case vssq_status_IMPORT_CREDS_FAILED_IMPORT_PRIVATE_KEY_FAILED:
            return k_message_import_creds_failed_import_private_key_failed;
        case vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG:
            return k_message_contact_validation_failed_username_too_long;
        case vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS:
            return k_message_contact_validation_failed_username_bad_chars;
        case vssq_status_CONTACT_VALIDATION_FAILED_PHONE_NUMBER_BAD_FORMAT:
            return k_message_contact_validation_failed_phone_number_bad_format;
        case vssq_status_CONTACT_VALIDATION_FAILED_EMAIL_BAD_FORMAT:
            return k_message_contact_validation_failed_email_bad_format;
        case vssq_status_MODIFY_GROUP_FAILED_PERMISSION_VIOLATION:
            return k_message_modify_group_failed_permission_violation;
        case vssq_status_ACCESS_GROUP_FAILED_PERMISSION_VIOLATION:
            return k_message_access_group_failed_permission_violation;
        case vssq_status_CREATE_GROUP_FAILED_CRYPTO_FAILED:
            return k_message_create_group_failed_crypto_failed;
        case vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED:
            return k_message_import_group_epoch_failed_parse_failed;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_SESSION_ID_DOESNT_MATCH:
            return k_message_process_group_message_failed_session_id_doesnt_match;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_EPOCH_NOT_FOUND:
            return k_message_process_group_message_failed_epoch_not_found;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_WRONG_KEY_TYPE:
            return k_message_process_group_message_failed_wrong_key_type;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_INVALID_SIGNATURE:
            return k_message_process_group_message_failed_invalid_signature;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_ED25519_FAILED:
            return k_message_process_group_message_failed_ed25519_failed;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_DUPLICATE_EPOCH:
            return k_message_process_group_message_failed_duplicate_epoch;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_PLAIN_TEXT_TOO_LONG:
            return k_message_process_group_message_failed_plain_text_too_long;
        case vssq_status_PROCESS_GROUP_MESSAGE_FAILED_CRYPTO_FAILED:
            return k_message_process_group_message_failed_crypto_failed;
        case vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_INVALID_ENCRYPTED_MESSAGE:
            return k_message_decrypt_regular_message_failed_invalid_encrypted_message;
        case vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_WRONG_PRIVATE_KEY:
            return k_message_decrypt_regular_message_failed_wrong_private_key;
        case vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_RECIPIENT_NOT_FOUND:
            return k_message_decrypt_regular_message_failed_recipient_not_found;
        case vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE:
            return k_message_decrypt_regular_message_failed_verify_signature;
        case vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED:
            return k_message_decrypt_regular_message_failed_crypto_failed;
        case vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED:
            return k_message_encrypt_regular_message_failed_crypto_failed;
        case vssq_status_CONTACTS_FAILED_SEND_REQUEST_FAILED:
            return k_message_contacts_failed_send_request_failed;
        case vssq_status_CONTACTS_FAILED_RESPONSE_WITH_ERROR:
            return k_message_contacts_failed_response_with_error;
        case vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED:
            return k_message_contacts_failed_parse_response_failed;
        case vssq_status_CLOUD_FS_FAILED_SEND_REQUEST_FAILED:
            return k_message_cloud_fs_failed_send_request_failed;
        case vssq_status_CLOUD_FS_FAILED_RESPONSE_WITH_ERROR:
            return k_message_cloud_fs_failed_response_with_error;
        case vssq_status_CLOUD_FS_FAILED_UNEXPECTED_CONTENT_TYPE:
            return k_message_cloud_fs_failed_unexpected_content_type;
        case vssq_status_CLOUD_FS_FAILED_PARSE_RESPONSE_FAILED:
            return k_message_cloud_fs_failed_parse_response_failed;
        default:
            return k_message_unknown_error;
    }
}

//
//  Return a message string from the given status.
//
VSSQ_PUBLIC vsc_str_t
vssq_error_message_from_error(const vssq_error_t *error) {

    VSSQ_ASSERT_PTR(error);
    return vssq_error_message_from_status(error->status);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
