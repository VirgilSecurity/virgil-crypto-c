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
//  Contains user private key and credentials (JWT) to the messenger services.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CREDS_H_INCLUDED
#define VSSQ_MESSENGER_CREDS_H_INCLUDED

#include "vssq_library.h"
#include "vssq_error.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_json_array.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSC/vssc_json_array.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Handle 'messenger creds' context.
//
#ifndef VSSQ_MESSENGER_CREDS_T_DEFINED
#define VSSQ_MESSENGER_CREDS_T_DEFINED
    typedef struct vssq_messenger_creds_t vssq_messenger_creds_t;
#endif // VSSQ_MESSENGER_CREDS_T_DEFINED

//
//  Return size of 'vssq_messenger_creds_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_creds_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_creds_init(vssq_messenger_creds_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_creds_cleanup(vssq_messenger_creds_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_creds_init_with(vssq_messenger_creds_t *self, vsc_str_t card_id, vsc_str_t username,
        const vscf_impl_t *private_key);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_new_with(vsc_str_t card_id, vsc_str_t username, const vscf_impl_t *private_key);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_creds_delete(const vssq_messenger_creds_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_creds_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_creds_destroy(vssq_messenger_creds_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_shallow_copy(vssq_messenger_creds_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_creds_shallow_copy_const(const vssq_messenger_creds_t *self);

//
//  Return identifier of the user Virgil Card.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_creds_card_id(const vssq_messenger_creds_t *self);

//
//  Return the username.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_creds_username(const vssq_messenger_creds_t *self);

//
//  Return the user private key.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_creds_private_key(const vssq_messenger_creds_t *self);

//
//  Return credentials as JSON object.
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_creds_to_json(const vssq_messenger_creds_t *self, vssq_error_t *error);

//
//  Parse credentials from JSON.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_from_json(const vssc_json_object_t *json_obj, vssq_error_t *error);

//
//  Parse credentials from JSON string.
//
VSSQ_PUBLIC vssq_messenger_creds_t *
vssq_messenger_creds_from_json_str(vsc_str_t json_str, vssq_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CREDS_H_INCLUDED
//  @end
