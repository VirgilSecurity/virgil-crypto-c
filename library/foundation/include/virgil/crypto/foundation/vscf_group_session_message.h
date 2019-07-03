//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  Class represents group session message
// --------------------------------------------------------------------------

#ifndef VSCF_GROUP_SESSION_MESSAGE_H_INCLUDED
#define VSCF_GROUP_SESSION_MESSAGE_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_group_session_message.h"
#include "vscf_group_msg_type.h"

#include <virgil/crypto/common/vsc_buffer.h>

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
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
//  Public integral constants.
//
enum {
    //
    //  Max message len
    //
    vscf_group_session_message_MAX_MESSAGE_LEN = 30222,
    //
    //  Message version
    //
    vscf_group_session_message_MESSAGE_VERSION = 1
};

//
//  Handle 'group session message' context.
//
typedef struct vscf_group_session_message_t vscf_group_session_message_t;

//
//  Return size of 'vscf_group_session_message_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_message_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_message_init(vscf_group_session_message_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_message_cleanup(vscf_group_session_message_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_message_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_message_delete(vscf_group_session_message_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_message_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_message_destroy(vscf_group_session_message_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_message_shallow_copy(vscf_group_session_message_t *self);

//
//  Returns message type.
//
VSCF_PUBLIC vscf_group_msg_type_t
vscf_group_session_message_get_type(const vscf_group_session_message_t *self);

//
//  Returns session id.
//  This method should be called only for group info type.
//
VSCF_PUBLIC vsc_data_t
vscf_group_session_message_get_session_id(const vscf_group_session_message_t *self);

//
//  Returns message sender id.
//  This method should be called only for regular message type.
//
VSCF_PUBLIC vsc_data_t
vscf_group_session_message_get_sender_id(const vscf_group_session_message_t *self);

//
//  Returns message epoch.
//
VSCF_PUBLIC uint32_t
vscf_group_session_message_get_epoch(const vscf_group_session_message_t *self);

//
//  Buffer len to serialize this class.
//
VSCF_PUBLIC size_t
vscf_group_session_message_serialize_len(const vscf_group_session_message_t *self);

//
//  Serializes instance.
//
VSCF_PUBLIC void
vscf_group_session_message_serialize(const vscf_group_session_message_t *self, vsc_buffer_t *output);

//
//  Deserializes instance.
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_message_deserialize(vsc_data_t input, vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_GROUP_SESSION_MESSAGE_H_INCLUDED
//  @end
