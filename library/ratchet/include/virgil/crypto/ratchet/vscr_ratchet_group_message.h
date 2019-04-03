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
//  Class represents ratchet message
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_GROUP_MESSAGE_H_INCLUDED
#define VSCR_RATCHET_GROUP_MESSAGE_H_INCLUDED

#include "vscr_library.h"
#include "vscr_error.h"
#include "vscr_ratchet_group_message.h"
#include "vscr_group_msg_type.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'ratchet group message' context.
//
typedef struct vscr_ratchet_group_message_t vscr_ratchet_group_message_t;

//
//  Return size of 'vscr_ratchet_group_message_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_init(vscr_ratchet_group_message_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_cleanup(vscr_ratchet_group_message_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_delete(vscr_ratchet_group_message_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_destroy(vscr_ratchet_group_message_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_shallow_copy(vscr_ratchet_group_message_t *self);

//
//  Returns message type.
//
VSCR_PUBLIC vscr_group_msg_type_t
vscr_ratchet_group_message_get_type(const vscr_ratchet_group_message_t *self);

VSCR_PUBLIC size_t
vscr_ratchet_group_message_get_pub_key_count(const vscr_ratchet_group_message_t *self);

VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_message_get_pub_key(const vscr_ratchet_group_message_t *self, vsc_data_t id);

//
//  Buffer len to serialize this class.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_message_serialize_len(vscr_ratchet_group_message_t *self);

//
//  Serializes instance.
//
VSCR_PUBLIC void
vscr_ratchet_group_message_serialize(vscr_ratchet_group_message_t *self, vsc_buffer_t *output);

//
//  Deserializes instance.
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_message_deserialize(vsc_data_t input, vscr_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_GROUP_MESSAGE_H_INCLUDED
//  @end
