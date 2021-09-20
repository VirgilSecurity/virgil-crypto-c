//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#include "vssc_error_message.h"
#include "vssc_memory.h"
#include "vssc_assert.h"

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

static const char k_message_not_found_chars[] = "Generic error for any find operation.";

static const vsc_str_t k_message_not_found = {
    k_message_not_found_chars,
    sizeof(k_message_not_found_chars) - 1
};

static const char k_message_decode_base64_url_failed_chars[] = "Failed to decode Base64URL string.";

static const vsc_str_t k_message_decode_base64_url_failed = {
    k_message_decode_base64_url_failed_chars,
    sizeof(k_message_decode_base64_url_failed_chars) - 1
};

static const char k_message_init_random_failed_chars[] = "Failed to initialize random module.";

static const vsc_str_t k_message_init_random_failed = {
    k_message_init_random_failed_chars,
    sizeof(k_message_init_random_failed_chars) - 1
};

static const char k_message_export_public_key_failed_chars[] = "Failed to export public key, underlying crypto returned an error.";

static const vsc_str_t k_message_export_public_key_failed = {
    k_message_export_public_key_failed_chars,
    sizeof(k_message_export_public_key_failed_chars) - 1
};

static const char k_message_import_public_key_failed_chars[] = "Failed to import public key, underlying crypto returned an error.";

static const vsc_str_t k_message_import_public_key_failed = {
    k_message_import_public_key_failed_chars,
    sizeof(k_message_import_public_key_failed_chars) - 1
};

static const char k_message_produce_signature_failed_chars[] = "Failed to produce signature, underlying crypto returned an error.";

static const vsc_str_t k_message_produce_signature_failed = {
    k_message_produce_signature_failed_chars,
    sizeof(k_message_produce_signature_failed_chars) - 1
};

static const char k_message_produce_public_key_id_failed_chars[] = "Failed to produce public key id.";

static const vsc_str_t k_message_produce_public_key_id_failed = {
    k_message_produce_public_key_id_failed_chars,
    sizeof(k_message_produce_public_key_id_failed_chars) - 1
};

static const char k_message_parse_jwt_failed_chars[] = "Failed to parse JWT.";

static const vsc_str_t k_message_parse_jwt_failed = {
    k_message_parse_jwt_failed_chars,
    sizeof(k_message_parse_jwt_failed_chars) - 1
};

static const char k_message_sign_jwt_failed_chars[] = "Failed to produce JWT signature.";

static const vsc_str_t k_message_sign_jwt_failed = {
    k_message_sign_jwt_failed_chars,
    sizeof(k_message_sign_jwt_failed_chars) - 1
};

static const char k_message_json_value_not_found_chars[] = "Requested value is not found within JSON object.";

static const vsc_str_t k_message_json_value_not_found = {
    k_message_json_value_not_found_chars,
    sizeof(k_message_json_value_not_found_chars) - 1
};

static const char k_message_json_value_type_mismatch_chars[] = "Actual JSON value type differs from the requested.";

static const vsc_str_t k_message_json_value_type_mismatch = {
    k_message_json_value_type_mismatch_chars,
    sizeof(k_message_json_value_type_mismatch_chars) - 1
};

static const char k_message_json_value_is_not_base64_chars[] = "Requested JSON binary value is not base64 encoded.";

static const vsc_str_t k_message_json_value_is_not_base64 = {
    k_message_json_value_is_not_base64_chars,
    sizeof(k_message_json_value_is_not_base64_chars) - 1
};

static const char k_message_parse_json_failed_chars[] = "Parse JSON string failed.";

static const vsc_str_t k_message_parse_json_failed = {
    k_message_parse_json_failed_chars,
    sizeof(k_message_parse_json_failed_chars) - 1
};

static const char k_message_http_send_request_failed_chars[] = "Failed to send HTTP request.";

static const vsc_str_t k_message_http_send_request_failed = {
    k_message_http_send_request_failed_chars,
    sizeof(k_message_http_send_request_failed_chars) - 1
};

static const char k_message_http_status_code_invalid_chars[] = "Got invalid HTTP status code.";

static const vsc_str_t k_message_http_status_code_invalid = {
    k_message_http_status_code_invalid_chars,
    sizeof(k_message_http_status_code_invalid_chars) - 1
};

static const char k_message_http_body_parse_failed_chars[] = "Failed to parse HTTP body.";

static const vsc_str_t k_message_http_body_parse_failed = {
    k_message_http_body_parse_failed_chars,
    sizeof(k_message_http_body_parse_failed_chars) - 1
};

static const char k_message_http_header_not_found_chars[] = "Cannot find HTTP header with a given name.";

static const vsc_str_t k_message_http_header_not_found = {
    k_message_http_header_not_found_chars,
    sizeof(k_message_http_header_not_found_chars) - 1
};

static const char k_message_http_url_invalid_format_chars[] = "Failed to parse HTTP URL.";

static const vsc_str_t k_message_http_url_invalid_format = {
    k_message_http_url_invalid_format_chars,
    sizeof(k_message_http_url_invalid_format_chars) - 1
};

static const char k_message_http_response_contains_service_error_chars[] = "Response processing failed because given HTTP Response contains Virgil Service error.";

static const vsc_str_t k_message_http_response_contains_service_error = {
    k_message_http_response_contains_service_error_chars,
    sizeof(k_message_http_response_contains_service_error_chars) - 1
};

static const char k_message_http_response_body_parse_failed_chars[] = "Given HTTP response body can not be parsed in an expected way.";

static const vsc_str_t k_message_http_response_body_parse_failed = {
    k_message_http_response_body_parse_failed_chars,
    sizeof(k_message_http_response_body_parse_failed_chars) - 1
};

static const char k_message_raw_card_content_parse_failed_chars[] = "Failed to parse card content.";

static const vsc_str_t k_message_raw_card_content_parse_failed = {
    k_message_raw_card_content_parse_failed_chars,
    sizeof(k_message_raw_card_content_parse_failed_chars) - 1
};

static const char k_message_raw_card_signature_parse_failed_chars[] = "Failed to parse card signature.";

static const vsc_str_t k_message_raw_card_signature_parse_failed = {
    k_message_raw_card_signature_parse_failed_chars,
    sizeof(k_message_raw_card_signature_parse_failed_chars) - 1
};

static const char k_message_raw_card_signature_verification_failed_chars[] = "Failed to verify one of the Raw Card signatures.";

static const vsc_str_t k_message_raw_card_signature_verification_failed = {
    k_message_raw_card_signature_verification_failed_chars,
    sizeof(k_message_raw_card_signature_verification_failed_chars) - 1
};

static const char k_message_card_version_is_not_supported_chars[] = "Failed to parse card, found card's version is not supported.";

static const vsc_str_t k_message_card_version_is_not_supported = {
    k_message_card_version_is_not_supported_chars,
    sizeof(k_message_card_version_is_not_supported_chars) - 1
};

static const char k_message_service_returned_invalid_card_chars[] = "The Card returned by Virgil Cards Service is not what was requested.";

static const vsc_str_t k_message_service_returned_invalid_card = {
    k_message_service_returned_invalid_card_chars,
    sizeof(k_message_service_returned_invalid_card_chars) - 1
};

//
//  Return a message string from the given status.
//
VSSC_PUBLIC vsc_str_t
vssc_error_message_from_status(vssc_status_t status) {

    switch(status) {
        case vssc_status_SUCCESS:
            return k_message_success;
        case vssc_status_INTERNAL_ERROR:
            return k_message_internal_error;
        case vssc_status_NOT_FOUND:
            return k_message_not_found;
        case vssc_status_DECODE_BASE64_URL_FAILED:
            return k_message_decode_base64_url_failed;
        case vssc_status_INIT_RANDOM_FAILED:
            return k_message_init_random_failed;
        case vssc_status_EXPORT_PUBLIC_KEY_FAILED:
            return k_message_export_public_key_failed;
        case vssc_status_IMPORT_PUBLIC_KEY_FAILED:
            return k_message_import_public_key_failed;
        case vssc_status_PRODUCE_SIGNATURE_FAILED:
            return k_message_produce_signature_failed;
        case vssc_status_PRODUCE_PUBLIC_KEY_ID_FAILED:
            return k_message_produce_public_key_id_failed;
        case vssc_status_PARSE_JWT_FAILED:
            return k_message_parse_jwt_failed;
        case vssc_status_SIGN_JWT_FAILED:
            return k_message_sign_jwt_failed;
        case vssc_status_JSON_VALUE_NOT_FOUND:
            return k_message_json_value_not_found;
        case vssc_status_JSON_VALUE_TYPE_MISMATCH:
            return k_message_json_value_type_mismatch;
        case vssc_status_JSON_VALUE_IS_NOT_BASE64:
            return k_message_json_value_is_not_base64;
        case vssc_status_PARSE_JSON_FAILED:
            return k_message_parse_json_failed;
        case vssc_status_HTTP_SEND_REQUEST_FAILED:
            return k_message_http_send_request_failed;
        case vssc_status_HTTP_STATUS_CODE_INVALID:
            return k_message_http_status_code_invalid;
        case vssc_status_HTTP_BODY_PARSE_FAILED:
            return k_message_http_body_parse_failed;
        case vssc_status_HTTP_HEADER_NOT_FOUND:
            return k_message_http_header_not_found;
        case vssc_status_HTTP_URL_INVALID_FORMAT:
            return k_message_http_url_invalid_format;
        case vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR:
            return k_message_http_response_contains_service_error;
        case vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED:
            return k_message_http_response_body_parse_failed;
        case vssc_status_RAW_CARD_CONTENT_PARSE_FAILED:
            return k_message_raw_card_content_parse_failed;
        case vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED:
            return k_message_raw_card_signature_parse_failed;
        case vssc_status_RAW_CARD_SIGNATURE_VERIFICATION_FAILED:
            return k_message_raw_card_signature_verification_failed;
        case vssc_status_CARD_VERSION_IS_NOT_SUPPORTED:
            return k_message_card_version_is_not_supported;
        case vssc_status_SERVICE_RETURNED_INVALID_CARD:
            return k_message_service_returned_invalid_card;
        default:
            return k_message_unknown_error;
    }
}

//
//  Return a message string from the given status.
//
VSSC_PUBLIC vsc_str_t
vssc_error_message_from_error(const vssc_error_t *error) {

    VSSC_ASSERT_PTR(error);
    return vssc_error_message_from_status(error->status);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
