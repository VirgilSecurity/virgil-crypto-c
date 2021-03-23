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
//  Information about a messenger user, i.e. username, Virgil Card, etc.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_USER_H_INCLUDED
#define VSSQ_MESSENGER_USER_H_INCLUDED

#include "vssq_library.h"
#include "vssq_error.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_card.h>
#   include <virgil/sdk/core/vssc_json_array.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_json_array.h>
#   include <VSSCore/vssc_card.h>
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
//  Handle 'messenger user' context.
//
#ifndef VSSQ_MESSENGER_USER_T_DEFINED
#define VSSQ_MESSENGER_USER_T_DEFINED
    typedef struct vssq_messenger_user_t vssq_messenger_user_t;
#endif // VSSQ_MESSENGER_USER_T_DEFINED

//
//  Return size of 'vssq_messenger_user_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_user_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_user_init(vssq_messenger_user_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_user_cleanup(vssq_messenger_user_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create an object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_user_init_with_card(vssq_messenger_user_t *self, const vssc_card_t *card);

//
//  Allocate class context and perform it's initialization.
//  Create an object with required fields.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_new_with_card(const vssc_card_t *card);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_user_delete(const vssq_messenger_user_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_user_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_user_destroy(vssq_messenger_user_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_shallow_copy(vssq_messenger_user_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_user_shallow_copy_const(const vssq_messenger_user_t *self);

//
//  Return a user's Card.
//
VSSQ_PUBLIC const vssc_card_t *
vssq_messenger_user_card(const vssq_messenger_user_t *self);

//
//  Return a user's identity (Card's identity).
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_identity(const vssq_messenger_user_t *self);

//
//  Return a user's public key (Card's public key).
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_user_public_key(const vssq_messenger_user_t *self);

//
//  Return a user's public key identifier (Card's public key identifier).
//
VSSQ_PUBLIC vsc_data_t
vssq_messenger_user_public_key_id(const vssq_messenger_user_t *self);

//
//  Return true if a username defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_username(const vssq_messenger_user_t *self);

//
//  Return username, or an empty string if username not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_username(const vssq_messenger_user_t *self);

//
//  Set an optional username.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_username(vssq_messenger_user_t *self, vsc_str_t username);

//
//  Return true if a phone number defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_phone_number(const vssq_messenger_user_t *self);

//
//  Return phone number, or an empty string if phone number not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_phone_number(const vssq_messenger_user_t *self);

//
//  Set an optional phone number.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_phone_number(vssq_messenger_user_t *self, vsc_str_t phone_number);

//
//  Return true if a email defined.
//
VSSQ_PUBLIC bool
vssq_messenger_user_has_email(const vssq_messenger_user_t *self);

//
//  Return email, or an empty string if email not defined.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_user_email(const vssq_messenger_user_t *self);

//
//  Set an optional email.
//
VSSQ_PUBLIC void
vssq_messenger_user_set_email(vssq_messenger_user_t *self, vsc_str_t email);

//
//  Return user as JSON object.
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_user_to_json(const vssq_messenger_user_t *self, vssq_error_t *error);

//
//  Parse user from JSON.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_from_json(const vssc_json_object_t *json_obj, const vscf_impl_t *random, vssq_error_t *error);

//
//  Parse user from JSON string.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_from_json_str(vsc_str_t json_str, const vscf_impl_t *random, vssq_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_USER_H_INCLUDED
//  @end
