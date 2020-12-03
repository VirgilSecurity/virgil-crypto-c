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
//  Helps to communicate with Virgil Keyknox Service.
// --------------------------------------------------------------------------

#ifndef VSSK_KEYKNOX_CLIENT_H_INCLUDED
#define VSSK_KEYKNOX_CLIENT_H_INCLUDED

#include "vssk_library.h"
#include "vssk_keyknox_entry.h"
#include "vssk_error.h"

#if !VSSK_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSK_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_http_response.h>
#   include <virgil/sdk/core/vssc_http_request.h>
#   include <virgil/sdk/core/vssc_string_list.h>
#endif

#if VSSK_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSK_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_http_response.h>
#   include <VSSCore/vssc_http_request.h>
#   include <VSSCore/vssc_string_list.h>
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

//
//  Handle 'keyknox client' context.
//
#ifndef VSSK_KEYKNOX_CLIENT_T_DEFINED
#define VSSK_KEYKNOX_CLIENT_T_DEFINED
    typedef struct vssk_keyknox_client_t vssk_keyknox_client_t;
#endif // VSSK_KEYKNOX_CLIENT_T_DEFINED

//
//  Return size of 'vssk_keyknox_client_t'.
//
VSSK_PUBLIC size_t
vssk_keyknox_client_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSK_PUBLIC void
vssk_keyknox_client_init(vssk_keyknox_client_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSK_PUBLIC void
vssk_keyknox_client_cleanup(vssk_keyknox_client_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSK_PUBLIC void
vssk_keyknox_client_init_with_base_url(vssk_keyknox_client_t *self, vsc_str_t url);

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_new_with_base_url(vsc_str_t url);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSK_PUBLIC void
vssk_keyknox_client_delete(const vssk_keyknox_client_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssk_keyknox_client_new ()'.
//
VSSK_PUBLIC void
vssk_keyknox_client_destroy(vssk_keyknox_client_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSK_PUBLIC vssk_keyknox_client_t *
vssk_keyknox_client_shallow_copy(vssk_keyknox_client_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSK_PUBLIC const vssk_keyknox_client_t *
vssk_keyknox_client_shallow_copy_const(const vssk_keyknox_client_t *self);

//
//  Create request that performs push operation.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_push(const vssk_keyknox_client_t *self, const vssk_keyknox_entry_t *new_entry);

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_push(const vssc_http_response_t *response, vssk_error_t *error);

//
//  Create request that performs pull operation.
//  Note, identity can be empty.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_pull(const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vsc_str_t identity);

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_pull(const vssc_http_response_t *response, vssk_error_t *error);

//
//  Create request that performs reset operation.
//
//  Note, all parameters can be empty.
//  Note, if identity is given, only "key" parameter can be optional.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_reset(const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vsc_str_t identity);

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_client_process_response_reset(const vssc_http_response_t *response, vssk_error_t *error);

//
//  Create request that performs get keys operation.
//
//  Note, all parameters can be empty.
//
VSSK_PUBLIC vssc_http_request_t *
vssk_keyknox_client_make_request_get_keys(const vssk_keyknox_client_t *self, vsc_str_t root, vsc_str_t path,
        vsc_str_t identity);

//
//  Map response to the correspond model.
//
VSSK_PUBLIC vssc_string_list_t *
vssk_keyknox_client_process_response_get_keys(const vssc_http_response_t *response, vssk_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSK_KEYKNOX_CLIENT_H_INCLUDED
//  @end
