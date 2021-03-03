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
//  Add and/or remove recipients and it's parameters within message info.
//
//  Usage:
//    1. Unpack binary message info that was obtained from RecipientCipher.
//    2. Add and/or remove key recipients.
//    3. Pack MessagInfo to the binary data.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_EDITOR_H_INCLUDED
#define VSCF_MESSAGE_INFO_EDITOR_H_INCLUDED

#include "vscf_library.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
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
//  Handle 'message info editor' context.
//
#ifndef VSCF_MESSAGE_INFO_EDITOR_T_DEFINED
#define VSCF_MESSAGE_INFO_EDITOR_T_DEFINED
    typedef struct vscf_message_info_editor_t vscf_message_info_editor_t;
#endif // VSCF_MESSAGE_INFO_EDITOR_T_DEFINED

//
//  Return size of 'vscf_message_info_editor_t'.
//
VSCF_PUBLIC size_t
vscf_message_info_editor_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_info_editor_init(vscf_message_info_editor_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_info_editor_cleanup(vscf_message_info_editor_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_info_editor_t *
vscf_message_info_editor_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_info_editor_delete(const vscf_message_info_editor_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_info_editor_new ()'.
//
VSCF_PUBLIC void
vscf_message_info_editor_destroy(vscf_message_info_editor_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_editor_t *
vscf_message_info_editor_shallow_copy(vscf_message_info_editor_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_message_info_editor_t *
vscf_message_info_editor_shallow_copy_const(const vscf_message_info_editor_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_message_info_editor_use_random(vscf_message_info_editor_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_message_info_editor_take_random(vscf_message_info_editor_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_message_info_editor_release_random(vscf_message_info_editor_t *self);

//
//  Set dependencies to it's defaults.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_setup_defaults(vscf_message_info_editor_t *self) VSCF_NODISCARD;

//
//  Unpack serialized message info.
//
//  Note that recipients can only be removed but not added.
//  Note, use "unlock" method to be able to add new recipients as well.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_unpack(vscf_message_info_editor_t *self, vsc_data_t message_info_data) VSCF_NODISCARD;

//
//  Decrypt encryption key this allows adding new recipients.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_unlock(vscf_message_info_editor_t *self, vsc_data_t owner_recipient_id,
        const vscf_impl_t *owner_private_key) VSCF_NODISCARD;

//
//  Add recipient defined with id and public key.
//
VSCF_PUBLIC vscf_status_t
vscf_message_info_editor_add_key_recipient(vscf_message_info_editor_t *self, vsc_data_t recipient_id,
        const vscf_impl_t *public_key) VSCF_NODISCARD;

//
//  Remove recipient with a given id.
//  Return false if recipient with given id was not found.
//
VSCF_PUBLIC bool
vscf_message_info_editor_remove_key_recipient(vscf_message_info_editor_t *self, vsc_data_t recipient_id);

//
//  Remove all existent recipients.
//
VSCF_PUBLIC void
vscf_message_info_editor_remove_all(vscf_message_info_editor_t *self);

//
//  Return length of serialized message info.
//  Actual length can be obtained right after applying changes.
//
VSCF_PUBLIC size_t
vscf_message_info_editor_packed_len(const vscf_message_info_editor_t *self);

//
//  Return serialized message info.
//  Precondition: this method can be called after "apply".
//
VSCF_PUBLIC void
vscf_message_info_editor_pack(vscf_message_info_editor_t *self, vsc_buffer_t *message_info);

//
//  Read message info prefix from the given data, and if it is valid,
//  return a length of bytes of the whole message info.
//
//  Zero returned if length can not be determined from the given data,
//  and this means that there is no message info at the data beginning.
//
VSCF_PUBLIC size_t
vscf_message_info_editor_read_prefix(vsc_data_t data);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_EDITOR_H_INCLUDED
//  @end
