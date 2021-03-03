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

#ifndef VSSC_CORE_SDK_PUBLIC_H_INCLUDED
#define VSSC_CORE_SDK_PUBLIC_H_INCLUDED

#include "vssc_platform.h"
#include "vssc_api.h"
#include "vssc_assert.h"
#include "vssc_impl.h"
#include "vssc_library.h"
#include "vssc_memory.h"
#include "vssc_status.h"

#if VSSC_BASE64_URL
#   include "vssc_base64_url.h"
#endif

#if VSSC_CARD
#   include "vssc_card.h"
#endif

#if VSSC_CARD_CLIENT
#   include "vssc_card_client.h"
#endif

#if VSSC_CARD_LIST
#   include "vssc_card_list.h"
#endif

#if VSSC_CARD_MANAGER
#   include "vssc_card_manager.h"
#endif

#if VSSC_ERROR
#   include "vssc_error.h"
#endif

#if VSSC_ERROR_MESSAGE
#   include "vssc_error_message.h"
#endif

#if VSSC_HTTP_CLIENT
#   include "vssc_http_client.h"
#endif

#if VSSC_HTTP_CLIENT_CURL
#   include "vssc_http_client_curl.h"
#endif

#if VSSC_HTTP_CLIENT_X
#   include "vssc_http_client_x.h"
#endif

#if VSSC_HTTP_HEADER
#   include "vssc_http_header.h"
#endif

#if VSSC_HTTP_HEADER_LIST
#   include "vssc_http_header_list.h"
#endif

#if VSSC_HTTP_REQUEST
#   include "vssc_http_request.h"
#endif

#if VSSC_HTTP_RESPONSE
#   include "vssc_http_response.h"
#endif

#if VSSC_JSON_ARRAY
#   include "vssc_json_array.h"
#endif

#if VSSC_JSON_OBJECT
#   include "vssc_json_object.h"
#endif

#if VSSC_JWT
#   include "vssc_jwt.h"
#endif

#if VSSC_JWT_GENERATOR
#   include "vssc_jwt_generator.h"
#endif

#if VSSC_KEY_HANDLER
#   include "vssc_key_handler.h"
#endif

#if VSSC_KEY_HANDLER_LIST
#   include "vssc_key_handler_list.h"
#endif

#if VSSC_NUMBER_LIST
#   include "vssc_number_list.h"
#endif

#if VSSC_RAW_CARD
#   include "vssc_raw_card.h"
#endif

#if VSSC_RAW_CARD_LIST
#   include "vssc_raw_card_list.h"
#endif

#if VSSC_RAW_CARD_SIGNATURE
#   include "vssc_raw_card_signature.h"
#endif

#if VSSC_RAW_CARD_SIGNATURE_LIST
#   include "vssc_raw_card_signature_list.h"
#endif

#if VSSC_RAW_CARD_SIGNER
#   include "vssc_raw_card_signer.h"
#endif

#if VSSC_RAW_CARD_VERIFIER
#   include "vssc_raw_card_verifier.h"
#endif

#if VSSC_STRING_LIST
#   include "vssc_string_list.h"
#endif

#if VSSC_STRING_MAP
#   include "vssc_string_map.h"
#endif

#if VSSC_UNIX_TIME
#   include "vssc_unix_time.h"
#endif

#if VSSC_VIRGIL_HTTP_CLIENT
#   include "vssc_virgil_http_client.h"
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
#endif // VSSC_CORE_SDK_PUBLIC_H_INCLUDED
//  @end
