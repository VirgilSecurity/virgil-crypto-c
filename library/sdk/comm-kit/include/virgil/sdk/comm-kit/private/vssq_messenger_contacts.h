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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provides access to the messenger contacts endpoints.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CONTACTS_H_INCLUDED
#define VSSQ_MESSENGER_CONTACTS_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_auth.h"
#include "vssq_error.h"
#include "vssq_status.h"

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_string_list.h>
#   include <virgil/sdk/core/vssc_string_map.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_string_map.h>
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
//  Handle 'messenger contacts' context.
//
#ifndef VSSQ_MESSENGER_CONTACTS_T_DEFINED
#define VSSQ_MESSENGER_CONTACTS_T_DEFINED
    typedef struct vssq_messenger_contacts_t vssq_messenger_contacts_t;
#endif // VSSQ_MESSENGER_CONTACTS_T_DEFINED

//
//  Return size of 'vssq_messenger_contacts_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_contacts_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_init(vssq_messenger_contacts_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_cleanup(vssq_messenger_contacts_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_contacts_t *
vssq_messenger_contacts_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_delete(const vssq_messenger_contacts_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_contacts_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_destroy(vssq_messenger_contacts_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_contacts_t *
vssq_messenger_contacts_shallow_copy(vssq_messenger_contacts_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_contacts_t *
vssq_messenger_contacts_shallow_copy_const(const vssq_messenger_contacts_t *self);

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_use_auth(vssq_messenger_contacts_t *self, vssq_messenger_auth_t *auth);

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_take_auth(vssq_messenger_contacts_t *self, vssq_messenger_auth_t *auth);

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_release_auth(vssq_messenger_contacts_t *self);

//
//  Discover given user names.
//
//  Return map username->identity.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_usernames(const vssq_messenger_contacts_t *self, const vssc_string_list_t *usernames,
        vssq_error_t *error);

//
//  Register user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_add_phone_number(const vssq_messenger_contacts_t *self, vsc_str_t phone_number) VSSQ_NODISCARD;

//
//  Confirm user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_confirm_phone_number(const vssq_messenger_contacts_t *self, vsc_str_t phone_number,
        vsc_str_t confirmation_code) VSSQ_NODISCARD;

//
//  Delete user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_delete_phone_number(const vssq_messenger_contacts_t *self,
        vsc_str_t phone_number) VSSQ_NODISCARD;

//
//  Discover given phone numbers.
//
//  Return map phone-number->identity.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_phone_numbers(const vssq_messenger_contacts_t *self,
        const vssc_string_list_t *phone_numbers, vssq_error_t *error);

//
//  Register user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_add_email(const vssq_messenger_contacts_t *self, vsc_str_t email) VSSQ_NODISCARD;

//
//  Confirm user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_confirm_email(const vssq_messenger_contacts_t *self, vsc_str_t email,
        vsc_str_t confirmation_code) VSSQ_NODISCARD;

//
//  Delete user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_delete_email(const vssq_messenger_contacts_t *self, vsc_str_t email) VSSQ_NODISCARD;

//
//  Discover given emails.
//
//  Return map email->identity.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_emails(const vssq_messenger_contacts_t *self, const vssc_string_list_t *emails,
        vssq_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CONTACTS_H_INCLUDED
//  @end
