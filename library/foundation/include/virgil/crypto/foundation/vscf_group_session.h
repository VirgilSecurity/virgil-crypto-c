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
//  Group chat encryption session.
// --------------------------------------------------------------------------

#ifndef VSCF_GROUP_SESSION_H_INCLUDED
#define VSCF_GROUP_SESSION_H_INCLUDED

#include "vscf_library.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_status.h"
#include "vscf_group_session_message.h"
#include "vscf_error.h"
#include "vscf_group_session_ticket.h"

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
//  Public integral constants.
//
enum {
    //
    //  Sender id len
    //
    vscf_group_session_SENDER_ID_LEN = 32,
    //
    //  Max plain text len
    //
    vscf_group_session_MAX_PLAIN_TEXT_LEN = 30000,
    //
    //  Max epochs count
    //
    vscf_group_session_MAX_EPOCHS_COUNT = 50,
    //
    //  Salt size
    //
    vscf_group_session_SALT_SIZE = 32
};

//
//  Handle 'group session' context.
//
#ifndef VSCF_GROUP_SESSION_T_DEFINED
#define VSCF_GROUP_SESSION_T_DEFINED
    typedef struct vscf_group_session_t vscf_group_session_t;
#endif // VSCF_GROUP_SESSION_T_DEFINED

//
//  Return size of 'vscf_group_session_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_init(vscf_group_session_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_cleanup(vscf_group_session_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_t *
vscf_group_session_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_delete(const vscf_group_session_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_destroy(vscf_group_session_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_t *
vscf_group_session_shallow_copy(vscf_group_session_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_group_session_t *
vscf_group_session_shallow_copy_const(const vscf_group_session_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_group_session_use_rng(vscf_group_session_t *self, vscf_impl_t *rng);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_group_session_take_rng(vscf_group_session_t *self, vscf_impl_t *rng);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_group_session_release_rng(vscf_group_session_t *self);

//
//  Returns current epoch.
//
VSCF_PUBLIC uint32_t
vscf_group_session_get_current_epoch(const vscf_group_session_t *self);

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_setup_defaults(vscf_group_session_t *self) VSCF_NODISCARD;

//
//  Returns session id.
//
VSCF_PUBLIC vsc_data_t
vscf_group_session_get_session_id(const vscf_group_session_t *self);

//
//  Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
//  Epoch message should be encrypted and signed by trusted group chat member (admin).
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_add_epoch(vscf_group_session_t *self, const vscf_group_session_message_t *message) VSCF_NODISCARD;

//
//  Encrypts data
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_encrypt(const vscf_group_session_t *self, vsc_data_t plain_text, const vscf_impl_t *private_key,
        vscf_error_t *error);

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCF_PUBLIC size_t
vscf_group_session_decrypt_len(const vscf_group_session_t *self, const vscf_group_session_message_t *message);

//
//  Decrypts message
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_decrypt(const vscf_group_session_t *self, const vscf_group_session_message_t *message,
        const vscf_impl_t *public_key, vsc_buffer_t *plain_text) VSCF_NODISCARD;

//
//  Creates ticket with new key for removing participants or proactive to rotate encryption key.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_create_group_ticket(const vscf_group_session_t *self, vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_GROUP_SESSION_H_INCLUDED
//  @end
