#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2020 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------

#   @warning
#   -------------------------------------------------------------------------
#   This file is fully generated by script 'cmake_files_codegen.gsl'.
#   It can be changed temporary for debug purposes only.
#   -------------------------------------------------------------------------
#   @end


include_guard()

option(VSSC_LIBRARY "Enable build of the 'core sdk' library" ON)
option(VSSC_MULTI_THREADING "Enable multi-threading safety for Cards Core SDK." ON)
option(VSSC_USE_DEFAULT_HTTP_CLIENT "" ON)
option(VSSC_HTTP_CLIENT "Enable interface 'http client'." ON)
option(VSSC_HTTP_CLIENT_CURL "Enable class 'http client curl'." ON)
option(VSSC_HTTP_CLIENT_X "Enable class 'http client x'." OFF)
option(VSSC_ERROR "Enable class 'error'." ON)
option(VSSC_JSON_OBJECT "Enable class 'json object'." ON)
option(VSSC_JSON_ARRAY "Enable class 'json array'." ON)
option(VSSC_UNIX_TIME "Enable class 'unix time'." ON)
option(VSSC_STRING_LIST "Enable class 'string list'." ON)
option(VSSC_NUMBER_LIST "Enable class 'number list'." ON)
option(VSSC_STRING_MAP "Enable class 'string map'." ON)
option(VSSC_STRING_MAP_BUCKET "Enable class 'string map bucket'." ON)
option(VSSC_BASE64_URL "Enable class 'base64 url'." ON)
option(VSSC_JWT "Enable class 'jwt'." ON)
option(VSSC_JWT_HEADER "Enable class 'jwt header'." ON)
option(VSSC_JWT_PAYLOAD "Enable class 'jwt payload'." ON)
option(VSSC_JWT_GENERATOR "Enable class 'jwt generator'." ON)
option(VSSC_HTTP_HEADER "Enable class 'http header'." ON)
option(VSSC_HTTP_HEADER_LIST "Enable class 'http header list'." ON)
option(VSSC_HTTP_REQUEST "Enable class 'http request'." ON)
option(VSSC_HTTP_RESPONSE "Enable class 'http response'." ON)
option(VSSC_VIRGIL_HTTP_CLIENT "Enable class 'virgil http client'." ON)
option(VSSC_VIRGIL_HTTP_CLIENT_DEBUG "" OFF)
option(VSSC_KEY_HANDLER "Enable class 'key handler'." ON)
option(VSSC_KEY_HANDLER_LIST "Enable class 'key handler list'." ON)
option(VSSC_CARD_CLIENT "Enable class 'card client'." ON)
option(VSSC_RAW_CARD "Enable class 'raw card'." ON)
option(VSSC_RAW_CARD_LIST "Enable class 'raw card list'." ON)
option(VSSC_RAW_CARD_SIGNER "Enable class 'raw card signer'." ON)
option(VSSC_RAW_CARD_VERIFIER "Enable class 'raw card verifier'." ON)
option(VSSC_RAW_CARD_SIGNATURE "Enable class 'raw card signature'." ON)
option(VSSC_RAW_CARD_SIGNATURE_LIST "Enable class 'raw card signature list'." ON)
option(VSSC_CARD "Enable class 'card'." ON)
option(VSSC_CARD_LIST "Enable class 'card list'." ON)
option(VSSC_CARD_MANAGER "Enable class 'card manager'." ON)
mark_as_advanced(
        VSSC_LIBRARY
        VSSC_MULTI_THREADING
        VSSC_USE_DEFAULT_HTTP_CLIENT
        VSSC_HTTP_CLIENT
        VSSC_HTTP_CLIENT_CURL
        VSSC_HTTP_CLIENT_X
        VSSC_ERROR
        VSSC_JSON_OBJECT
        VSSC_JSON_ARRAY
        VSSC_UNIX_TIME
        VSSC_STRING_LIST
        VSSC_NUMBER_LIST
        VSSC_STRING_MAP
        VSSC_STRING_MAP_BUCKET
        VSSC_BASE64_URL
        VSSC_JWT
        VSSC_JWT_HEADER
        VSSC_JWT_PAYLOAD
        VSSC_JWT_GENERATOR
        VSSC_HTTP_HEADER
        VSSC_HTTP_HEADER_LIST
        VSSC_HTTP_REQUEST
        VSSC_HTTP_RESPONSE
        VSSC_VIRGIL_HTTP_CLIENT
        VSSC_VIRGIL_HTTP_CLIENT_DEBUG
        VSSC_KEY_HANDLER
        VSSC_KEY_HANDLER_LIST
        VSSC_CARD_CLIENT
        VSSC_RAW_CARD
        VSSC_RAW_CARD_LIST
        VSSC_RAW_CARD_SIGNER
        VSSC_RAW_CARD_VERIFIER
        VSSC_RAW_CARD_SIGNATURE
        VSSC_RAW_CARD_SIGNATURE_LIST
        VSSC_CARD
        VSSC_CARD_LIST
        VSSC_CARD_MANAGER
        )

if(VSSC_USE_DEFAULT_HTTP_CLIENT AND NOT VSSC_HTTP_CLIENT_CURL AND NOT VSSC_HTTP_CLIENT_X)
    message("-- error --")
    message("--")
    message("Feature VSSC_USE_DEFAULT_HTTP_CLIENT depends on one of the features:")
    message("     VSSC_HTTP_CLIENT_CURL, VSSC_HTTP_CLIENT_X - which are disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_HTTP_CLIENT_CURL AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSC_HTTP_CLIENT_CURL depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_HTTP_CLIENT_CURL AND NOT VSC_STR_MUTABLE)
    message("-- error --")
    message("--")
    message("Feature VSSC_HTTP_CLIENT_CURL depends on the feature:")
    message("     VSC_STR_MUTABLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_HTTP_CLIENT_CURL AND NOT VSSC_HTTP_RESPONSE)
    message("-- error --")
    message("--")
    message("Feature VSSC_HTTP_CLIENT_CURL depends on the feature:")
    message("     VSSC_HTTP_RESPONSE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_HTTP_CLIENT_X AND NOT APPLE)
    message("-- error --")
    message("--")
    message("Feature VSSC_HTTP_CLIENT_X depends on the feature:")
    message("     APPLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JSON_OBJECT AND NOT VSC_STR_MUTABLE)
    message("-- error --")
    message("--")
    message("Feature VSSC_JSON_OBJECT depends on the feature:")
    message("     VSC_STR_MUTABLE - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JSON_OBJECT AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSC_JSON_OBJECT depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JSON_OBJECT AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSC_JSON_OBJECT depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JSON_ARRAY AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_JSON_ARRAY depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_STRING_MAP AND NOT VSSC_STRING_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSC_STRING_MAP depends on the feature:")
    message("     VSSC_STRING_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_STRING_MAP AND NOT VSSC_STRING_MAP_BUCKET)
    message("-- error --")
    message("--")
    message("Feature VSSC_STRING_MAP depends on the feature:")
    message("     VSSC_STRING_MAP_BUCKET - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_BASE64_URL AND NOT VSCF_BASE64)
    message("-- error --")
    message("--")
    message("Feature VSSC_BASE64_URL depends on the feature:")
    message("     VSCF_BASE64 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT AND NOT VSSC_BASE64_URL)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT depends on the feature:")
    message("     VSSC_BASE64_URL - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_HEADER AND NOT VSSC_BASE64_URL)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_HEADER depends on the feature:")
    message("     VSSC_BASE64_URL - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_HEADER AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_HEADER depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_PAYLOAD AND NOT VSSC_BASE64_URL)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_PAYLOAD depends on the feature:")
    message("     VSSC_BASE64_URL - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_PAYLOAD AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_PAYLOAD depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_GENERATOR AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_GENERATOR depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_GENERATOR AND NOT VSSC_BASE64_URL)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_GENERATOR depends on the feature:")
    message("     VSSC_BASE64_URL - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_GENERATOR AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_GENERATOR depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_JWT_GENERATOR AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSSC_JWT_GENERATOR depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_HTTP_RESPONSE AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_HTTP_RESPONSE depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_VIRGIL_HTTP_CLIENT AND NOT VSSC_USE_DEFAULT_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSC_VIRGIL_HTTP_CLIENT depends on the feature:")
    message("     VSSC_USE_DEFAULT_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_VIRGIL_HTTP_CLIENT AND NOT VSSC_HTTP_CLIENT)
    message("-- error --")
    message("--")
    message("Feature VSSC_VIRGIL_HTTP_CLIENT depends on the feature:")
    message("     VSSC_HTTP_CLIENT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_CLIENT AND NOT VSC_STR_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_CLIENT depends on the feature:")
    message("     VSC_STR_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_CLIENT AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_CLIENT depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_CLIENT AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_CLIENT depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_CLIENT AND NOT VSSC_RAW_CARD_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_CLIENT depends on the feature:")
    message("     VSSC_RAW_CARD_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD AND NOT VSSC_JSON_ARRAY)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD depends on the feature:")
    message("     VSSC_JSON_ARRAY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD_SIGNER AND NOT VSCF_SIGNER)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD_SIGNER depends on the feature:")
    message("     VSCF_SIGNER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD_SIGNER AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD_SIGNER depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD_SIGNER AND NOT VSCF_PRIVATE_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD_SIGNER depends on the feature:")
    message("     VSCF_PRIVATE_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD_VERIFIER AND NOT VSCF_VERIFIER)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD_VERIFIER depends on the feature:")
    message("     VSCF_VERIFIER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_RAW_CARD_SIGNATURE AND NOT VSSC_JSON_OBJECT)
    message("-- error --")
    message("--")
    message("Feature VSSC_RAW_CARD_SIGNATURE depends on the feature:")
    message("     VSSC_JSON_OBJECT - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD AND NOT VSCF_PUBLIC_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD depends on the feature:")
    message("     VSCF_PUBLIC_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD AND NOT VSC_BUFFER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD depends on the feature:")
    message("     VSC_BUFFER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD AND NOT VSCF_SHA512)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD depends on the feature:")
    message("     VSCF_SHA512 - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD AND NOT VSCF_BINARY)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD depends on the feature:")
    message("     VSCF_BINARY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD AND NOT VSSC_CARD_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD depends on the feature:")
    message("     VSSC_CARD_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSSC_UNIX_TIME)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSSC_UNIX_TIME - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSSC_RAW_CARD_VERIFIER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSSC_RAW_CARD_VERIFIER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSSC_RAW_CARD_SIGNER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSSC_RAW_CARD_SIGNER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSSC_CARD)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSSC_CARD - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSSC_CARD_LIST)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSSC_CARD_LIST - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSCF_PRIVATE_KEY)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSCF_PRIVATE_KEY - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSCF_KEY_PROVIDER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSCF_KEY_PROVIDER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSCF_SIGNER)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSCF_SIGNER - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()

if(VSSC_CARD_MANAGER AND NOT VSCF_CTR_DRBG)
    message("-- error --")
    message("--")
    message("Feature VSSC_CARD_MANAGER depends on the feature:")
    message("     VSCF_CTR_DRBG - which is disabled.")
    message("--")
    message(FATAL_ERROR)
endif()
