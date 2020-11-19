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
//  This is an umbrella header that includes library private headers.
// --------------------------------------------------------------------------

#ifndef VSSC_CORE_SDK_PRIVATE_H_INCLUDED
#define VSSC_CORE_SDK_PRIVATE_H_INCLUDED

#include "vssc_platform.h"
#include "vssc_api_private.h"
#include "vssc_atomic.h"
#include "vssc_card_list_private.h"
#include "vssc_card_private.h"
#include "vssc_impl_private.h"
#include "vssc_json_array_private.h"
#include "vssc_json_object_private.h"
#include "vssc_jwt_private.h"
#include "vssc_key_handler_list_private.h"
#include "vssc_key_handler_private.h"
#include "vssc_raw_card_list_private.h"

#if VSSC_CARD
#   include "vssc_card_defs.h"
#endif

#if VSSC_CARD_CLIENT
#   include "vssc_card_client_defs.h"
#endif

#if VSSC_CARD_LIST
#   include "vssc_card_list_defs.h"
#endif

#if VSSC_CARD_MANAGER
#   include "vssc_card_manager_defs.h"
#endif

#if VSSC_HTTP_CLIENT
#   include "vssc_http_client_api.h"
#endif

#if VSSC_HTTP_CLIENT_CURL
#   include "vssc_http_client_curl_defs.h"
#endif

#if VSSC_HTTP_CLIENT_X
#   include "vssc_http_client_x_defs.h"
#endif

#if VSSC_HTTP_HEADER
#   include "vssc_http_header_defs.h"
#endif

#if VSSC_HTTP_HEADER_LIST
#   include "vssc_http_header_list_defs.h"
#endif

#if VSSC_HTTP_REQUEST
#   include "vssc_http_request_defs.h"
#endif

#if VSSC_HTTP_RESPONSE
#   include "vssc_http_response_defs.h"
#endif

#if VSSC_JSON_ARRAY
#   include "vssc_json_array_defs.h"
#endif

#if VSSC_JSON_OBJECT
#   include "vssc_json_object_defs.h"
#endif

#if VSSC_JWT
#   include "vssc_jwt_defs.h"
#endif

#if VSSC_JWT_GENERATOR
#   include "vssc_jwt_generator_defs.h"
#endif

#if VSSC_JWT_HEADER
#   include "vssc_jwt_header.h"
#   include "vssc_jwt_header_defs.h"
#endif

#if VSSC_JWT_PAYLOAD
#   include "vssc_jwt_payload.h"
#   include "vssc_jwt_payload_defs.h"
#endif

#if VSSC_KEY_HANDLER
#   include "vssc_key_handler_defs.h"
#endif

#if VSSC_KEY_HANDLER_LIST
#   include "vssc_key_handler_list_defs.h"
#endif

#if VSSC_NUMBER_LIST
#   include "vssc_number_list_defs.h"
#endif

#if VSSC_RAW_CARD
#   include "vssc_raw_card_defs.h"
#endif

#if VSSC_RAW_CARD_LIST
#   include "vssc_raw_card_list_defs.h"
#endif

#if VSSC_RAW_CARD_SIGNATURE
#   include "vssc_raw_card_signature_defs.h"
#endif

#if VSSC_RAW_CARD_SIGNATURE_LIST
#   include "vssc_raw_card_signature_list_defs.h"
#endif

#if VSSC_RAW_CARD_SIGNER
#   include "vssc_raw_card_signer_defs.h"
#endif

#if VSSC_STRING_LIST
#   include "vssc_string_list_defs.h"
#endif

#if VSSC_VIRGIL_HTTP_RESPONSE
#   include "vssc_virgil_http_response_defs.h"
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
#endif // VSSC_CORE_SDK_PRIVATE_H_INCLUDED
//  @end
