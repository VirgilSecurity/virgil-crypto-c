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

#include "vssb_error_message.h"
#include "vssb_memory.h"
#include "vssb_assert.h"

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

static const char k_message_http_response_parse_failed_chars[] = "Given HTTP response body can not be parsed in an expected way.";

static const vsc_str_t k_message_http_response_parse_failed = {
    k_message_http_response_parse_failed_chars,
    sizeof(k_message_http_response_parse_failed_chars) - 1
};

static const char k_message_http_response_error_chars[] = "Given HTTP response handles unexpected status code.";

static const vsc_str_t k_message_http_response_error = {
    k_message_http_response_error_chars,
    sizeof(k_message_http_response_error_chars) - 1
};

static const char k_message_http_service_error_server_internal_error_chars[] = "Got HTTP response with a service error - internal server error - status code 500.";

static const vsc_str_t k_message_http_service_error_server_internal_error = {
    k_message_http_service_error_server_internal_error_chars,
    sizeof(k_message_http_service_error_server_internal_error_chars) - 1
};

static const char k_message_http_service_error_bad_blinded_point_data_chars[] = "Got HTTP response with a service error - bad blinded point data - status code 400.";

static const vsc_str_t k_message_http_service_error_bad_blinded_point_data = {
    k_message_http_service_error_bad_blinded_point_data_chars,
    sizeof(k_message_http_service_error_bad_blinded_point_data_chars) - 1
};

static const char k_message_http_service_error_invalid_json_chars[] = "Got HTTP response with a service error - invalid json - status code 400.";

static const vsc_str_t k_message_http_service_error_invalid_json = {
    k_message_http_service_error_invalid_json_chars,
    sizeof(k_message_http_service_error_invalid_json_chars) - 1
};

static const char k_message_http_service_error_undefined_chars[] = "Got HTTP response with a service error - undefined error - status code 400.";

static const vsc_str_t k_message_http_service_error_undefined = {
    k_message_http_service_error_undefined_chars,
    sizeof(k_message_http_service_error_undefined_chars) - 1
};

//
//  Return a message string from the given status.
//
VSSB_PUBLIC vsc_str_t
vssb_error_message_from_status(vssb_status_t status) {

    switch(status) {
        case vssb_status_SUCCESS:
            return k_message_success;
        case vssb_status_INTERNAL_ERROR:
            return k_message_internal_error;
        case vssb_status_HTTP_RESPONSE_PARSE_FAILED:
            return k_message_http_response_parse_failed;
        case vssb_status_HTTP_RESPONSE_ERROR:
            return k_message_http_response_error;
        case vssb_status_HTTP_SERVICE_ERROR_SERVER_INTERNAL_ERROR:
            return k_message_http_service_error_server_internal_error;
        case vssb_status_HTTP_SERVICE_ERROR_BAD_BLINDED_POINT_DATA:
            return k_message_http_service_error_bad_blinded_point_data;
        case vssb_status_HTTP_SERVICE_ERROR_INVALID_JSON:
            return k_message_http_service_error_invalid_json;
        case vssb_status_HTTP_SERVICE_ERROR_UNDEFINED:
            return k_message_http_service_error_undefined;
        default:
            return k_message_unknown_error;
    }
}

//
//  Return a message string from the given status.
//
VSSB_PUBLIC vsc_str_t
vssb_error_message_from_error(const vssb_error_t *error) {

    VSSB_ASSERT_PTR(error);
    return vssb_error_message_from_status(error->status);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
