//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#ifndef VSCR_RATCHET_MESSAGE_H_INCLUDED
#define VSCR_RATCHET_MESSAGE_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_common.h"
#include "vscr_error_ctx.h"
#include "vscr_ratchet_message.h"
#include "vscr_msg_type.h"

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
//  Handle 'ratchet message' context.
//
typedef struct vscr_ratchet_message_t vscr_ratchet_message_t;

//
//  Return size of 'vscr_ratchet_message_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_message_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_message_init(vscr_ratchet_message_t *ratchet_message);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_message_cleanup(vscr_ratchet_message_t *ratchet_message);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_message_delete(vscr_ratchet_message_t *ratchet_message);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_message_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_message_destroy(vscr_ratchet_message_t **ratchet_message_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_shallow_copy(vscr_ratchet_message_t *ratchet_message);

//
//  Returns message type.
//
VSCR_PUBLIC vscr_msg_type_t
vscr_ratchet_message_get_type(vscr_ratchet_message_t *ratchet_message);

//
//  Returns long-term public key, if message is prekey message.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_long_term_public_key(vscr_ratchet_message_t *ratchet_message);

//
//  Computes long-term public key id. Can be used to identify key in key storage.
//  Do not use this method if long-term public key is empty.
//
VSCR_PUBLIC void
vscr_ratchet_message_compute_long_term_public_key_id(vscr_ratchet_message_t *ratchet_message, vsc_buffer_t *buffer);

//
//  Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_message_get_one_time_public_key(vscr_ratchet_message_t *ratchet_message);

//
//  Computes one-term public key id. Can be used to identify key in key storage.
//  Do not use this method if long-term public key is empty.
//
VSCR_PUBLIC void
vscr_ratchet_message_compute_one_time_public_key_id(vscr_ratchet_message_t *ratchet_message, vsc_buffer_t *buffer);

//
//  Buffer len to serialize this class.
//
VSCR_PUBLIC size_t
vscr_ratchet_message_serialize_len(vscr_ratchet_message_t *ratchet_message);

//
//  Serializes instance.
//
VSCR_PUBLIC void
vscr_ratchet_message_serialize(vscr_ratchet_message_t *ratchet_message, vsc_buffer_t *output);

//
//  Deserializes instance.
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_message_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_MESSAGE_H_INCLUDED
//  @end
