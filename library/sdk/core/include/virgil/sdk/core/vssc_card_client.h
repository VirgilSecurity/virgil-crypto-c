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
//  Helps to communicate with Virgil Card Service.
// --------------------------------------------------------------------------

#ifndef VSSC_CARD_CLIENT_H_INCLUDED
#define VSSC_CARD_CLIENT_H_INCLUDED

#include "vssc_library.h"
#include "vssc_raw_card.h"
#include "vssc_http_request.h"
#include "vssc_virgil_http_response.h"
#include "vssc_error.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
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
//  Handle 'card client' context.
//
#ifndef VSSC_CARD_CLIENT_T_DEFINED
#define VSSC_CARD_CLIENT_T_DEFINED
    typedef struct vssc_card_client_t vssc_card_client_t;
#endif // VSSC_CARD_CLIENT_T_DEFINED

//
//  Return size of 'vssc_card_client_t'.
//
VSSC_PUBLIC size_t
vssc_card_client_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_client_init(vssc_card_client_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_client_cleanup(vssc_card_client_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSC_PUBLIC void
vssc_card_client_init_with_base_url(vssc_card_client_t *self, vsc_str_t url);

//
//  Allocate class context and perform it's initialization.
//  Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_new_with_base_url(vsc_str_t url);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_client_delete(const vssc_card_client_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_client_new ()'.
//
VSSC_PUBLIC void
vssc_card_client_destroy(vssc_card_client_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_client_t *
vssc_card_client_shallow_copy(vssc_card_client_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_card_client_t *
vssc_card_client_shallow_copy_const(const vssc_card_client_t *self);

//
//  Create request that creates Virgil Card instance on the Virgil Cards Service.
//
//  Also makes the Card accessible for search/get queries from other users.
//  Note, "raw card" should contain appropriate signatures.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_publish_card(const vssc_card_client_t *self, const vssc_raw_card_t *raw_card);

//
//  Map response to the correspond model.
//  Return "raw card" of published Card.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_client_process_response_publish_card(const vssc_virgil_http_response_t *response, vssc_error_t *error);

//
//  Create request that returns card from the Virgil Cards Service with given ID, if exists.
//
VSSC_PUBLIC vssc_http_request_t *
vssc_card_client_make_request_get_card(const vssc_card_client_t *self, vsc_str_t card_id);

//
//  Map response to the correspond model.
//  Return "raw card" of if Card was found.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_client_process_response_get_card(const vssc_virgil_http_response_t *response, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_CARD_CLIENT_H_INCLUDED
//  @end
