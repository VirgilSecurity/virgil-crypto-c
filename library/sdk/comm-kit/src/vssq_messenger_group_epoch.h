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
//  Contains credentials of a group session related to the specifc epoch.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_GROUP_EPOCH_H_INCLUDED
#define VSSQ_MESSENGER_GROUP_EPOCH_H_INCLUDED

#include "vssq_library.h"
#include "vssq_error.h"

#include <virgil/sdk/core/vssc_json_array.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_string_list.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_group_session_message.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSCore/vssc_json_array.h>
#   include <VSSCore/vssc_string_list.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_group_session_message.h>
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
//  Handle 'messenger group epoch' context.
//
#ifndef VSSQ_MESSENGER_GROUP_EPOCH_T_DEFINED
#define VSSQ_MESSENGER_GROUP_EPOCH_T_DEFINED
    typedef struct vssq_messenger_group_epoch_t vssq_messenger_group_epoch_t;
#endif // VSSQ_MESSENGER_GROUP_EPOCH_T_DEFINED

//
//  Return size of 'vssq_messenger_group_epoch_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_init(vssq_messenger_group_epoch_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_cleanup(vssq_messenger_group_epoch_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_init_with_disown(vssq_messenger_group_epoch_t *self,
        const vscf_group_session_message_t *group_info_message, vssc_string_list_t **participant_identities_ref);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_new_with_disown(const vscf_group_session_message_t *group_info_message,
        vssc_string_list_t **participant_identities_ref);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_delete(const vssq_messenger_group_epoch_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_group_epoch_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_group_epoch_destroy(vssq_messenger_group_epoch_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_shallow_copy(vssq_messenger_group_epoch_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_shallow_copy_const(const vssq_messenger_group_epoch_t *self);

//
//  Return group epoch serial number.
//
VSSQ_PUBLIC size_t
vssq_messenger_group_epoch_num(const vssq_messenger_group_epoch_t *self);

//
//  Return group epoch info and credentials.
//
VSSQ_PUBLIC const vscf_group_session_message_t *
vssq_messenger_group_epoch_group_info_message(const vssq_messenger_group_epoch_t *self);

//
//  Return participant identities (Card's identities) that have access to this epoch.
//
VSSQ_PUBLIC const vssc_string_list_t *
vssq_messenger_group_epoch_participant_identities(const vssq_messenger_group_epoch_t *self);

//
//  Return epoch as JSON object.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssc_json_object_t *
vssq_messenger_group_epoch_to_json(const vssq_messenger_group_epoch_t *self);

//
//  Parse epoch from JSON.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_from_json(const vssc_json_object_t *json_obj, vssq_error_t *error);

//
//  Parse epoch from JSON string.
//
//  JSON format:
//  {
//      "group_message" : "BASE64(GroupMessage)"
//      "participants" : ["identity1", "identity2", ...]
//  }
//
VSSQ_PUBLIC vssq_messenger_group_epoch_t *
vssq_messenger_group_epoch_from_json_str(vsc_str_t json_str, vssq_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_GROUP_EPOCH_H_INCLUDED
//  @end
