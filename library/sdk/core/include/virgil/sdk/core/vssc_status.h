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
//  Defines the library status codes.
// --------------------------------------------------------------------------

#ifndef VSSC_STATUS_H_INCLUDED
#define VSSC_STATUS_H_INCLUDED

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

//
//  Defines the library status codes.
//
enum vssc_status_t {
    //
    //  No errors was occurred.
    //
    vssc_status_SUCCESS = 0,
    //
    //  Met internal inconsistency.
    //
    vssc_status_INTERNAL_ERROR = -1,
    //
    //  Requested list item is not found.
    //
    vssc_status_LIST_ITEM_NOT_FOUND = -2,
    //
    //  Faled to decode Base64URL string.
    //
    vssc_status_DECODE_BASE64_URL_FAILED = -101,
    //
    //  Faled to initialize random module.
    //
    vssc_status_INIT_RANDOM_FAILED = -102,
    //
    //  Faled to export public key, underlying crypto returned an error.
    //
    vssc_status_EXPORT_PUBLIC_KEY_FAILED = -103,
    //
    //  Faled to import public key, underlying crypto returned an error.
    //
    vssc_status_IMPORT_PUBLIC_KEY_FAILED = -104,
    //
    //  Faled to produce signature, underlying crypto returned an error.
    //
    vssc_status_PRODUCE_SIGNATURE_FAILED = -105,
    //
    //  Faled to produce public key id.
    //
    vssc_status_PRODUCE_PUBLIC_KEY_ID_FAILED = -106,
    //
    //  Failed to parse JWT.
    //
    vssc_status_PARSE_JWT_FAILED = -201,
    //
    //  Failed to produce JWT signature.
    //
    vssc_status_SIGN_JWT_FAILED = -202,
    //
    //  Requested value is not found within JSON object.
    //
    vssc_status_JSON_VALUE_NOT_FOUND = -203,
    //
    //  Actual JSON value type differs from the requested.
    //
    vssc_status_JSON_VALUE_TYPE_MISMATCH = -204,
    //
    //  Requested JSON binary value is not base64 encoded.
    //
    vssc_status_JSON_VALUE_IS_NOT_BASE64 = -205,
    //
    //  Parse JSON string failed.
    //
    vssc_status_PARSE_JSON_FAILED = -206,
    //
    //  Failed to send HTTP request.
    //
    vssc_status_HTTP_SEND_REQUEST_FAILED = -301,
    //
    //  Got invalid HTTP status code.
    //
    vssc_status_HTTP_STATUS_CODE_INVALID = -302,
    //
    //  Failed to parse HTTP body.
    //
    vssc_status_HTTP_BODY_PARSE_FAILED = -303,
    //
    //  Cannot find HTTP header with a given name.
    //
    vssc_status_HTTP_HEADER_NOT_FOUND = -304,
    //
    //  Response processing failed because given HTTP Response contains Virgil Service error.
    //
    vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR = -401,
    //
    //  Given HTTP response body can not be parsed in an expected way.
    //
    vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED = -402,
    //
    //  Failed to parse card content.
    //
    vssc_status_RAW_CARD_CONTENT_PARSE_FAILED = -501,
    //
    //  Failed to parse card signature.
    //
    vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED = -502,
    //
    //  Failed to verify one of the Raw Card signatures.
    //
    vssc_status_RAW_CARD_SIGNATURE_VERIFICATION_FAILED = -503,
    //
    //  Failed to parse card, found card's version is not supported.
    //
    vssc_status_CARD_VERSION_IS_NOT_SUPPORTED = -504,
    //
    //  The Card returned by Virgil Cards Service is not what was requested.
    //
    vssc_status_SERVICE_RETURNED_INVALID_CARD = -505
};
#ifndef VSSC_STATUS_T_DEFINED
#define VSSC_STATUS_T_DEFINED
    typedef enum vssc_status_t vssc_status_t;
#endif // VSSC_STATUS_T_DEFINED


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_STATUS_H_INCLUDED
//  @end
