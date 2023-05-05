//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Class for ratchet session between 2 participants
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_SESSION_H_INCLUDED
#define VSCR_RATCHET_SESSION_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_common.h"
#include "vscr_ratchet_message.h"
#include "vscr_error.h"
#include "vscr_ratchet_session.h"
#include "vscr_status.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'ratchet session' context.
//
typedef struct vscr_ratchet_session_t vscr_ratchet_session_t;

//
//  Return size of 'vscr_ratchet_session_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_session_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_session_init(vscr_ratchet_session_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_session_cleanup(vscr_ratchet_session_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_session_delete(vscr_ratchet_session_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_session_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_session_destroy(vscr_ratchet_session_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_shallow_copy(vscr_ratchet_session_t *self);

//
//  Random used to generate keys
//
//  Note, ownership is shared.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_rng(vscr_ratchet_session_t *self, vscf_impl_t *rng);

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_rng(vscr_ratchet_session_t *self, vscf_impl_t *rng);

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_rng(vscr_ratchet_session_t *self);

//
//  Setups default dependencies:
//      - RNG: CTR DRBG
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_setup_defaults(vscr_ratchet_session_t *self) VSCR_NODISCARD;

//
//  Initiates session
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_initiate(vscr_ratchet_session_t *self, const vscf_impl_t *sender_identity_private_key,
        vsc_data_t sender_identity_key_id, const vscf_impl_t *receiver_identity_public_key,
        vsc_data_t receiver_identity_key_id, vscf_impl_t *receiver_long_term_public_key,
        vsc_data_t receiver_long_term_key_id, vscf_impl_t *receiver_one_time_public_key,
        vsc_data_t receiver_one_time_key_id, bool enable_post_quantum) VSCR_NODISCARD;

//
//  Initiates session
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_initiate_no_one_time_key(vscr_ratchet_session_t *self,
        const vscf_impl_t *sender_identity_private_key, vsc_data_t sender_identity_key_id,
        const vscf_impl_t *receiver_identity_public_key, vsc_data_t receiver_identity_key_id,
        vscf_impl_t *receiver_long_term_public_key, vsc_data_t receiver_long_term_key_id,
        bool enable_post_quantum) VSCR_NODISCARD;

//
//  Responds to session initiation
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_respond(vscr_ratchet_session_t *self, vscf_impl_t *sender_identity_public_key,
        const vscf_impl_t *receiver_identity_private_key, const vscf_impl_t *receiver_long_term_private_key,
        const vscf_impl_t *receiver_one_time_private_key, const vscr_ratchet_message_t *message,
        bool enable_post_quantum) VSCR_NODISCARD;

//
//  Responds to session initiation
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_respond_no_one_time_key(vscr_ratchet_session_t *self, vscf_impl_t *sender_identity_public_key,
        const vscf_impl_t *receiver_identity_private_key, const vscf_impl_t *receiver_long_term_private_key,
        const vscr_ratchet_message_t *message, bool enable_post_quantum) VSCR_NODISCARD;

//
//  Returns flag that indicates is this session was initiated or responded
//
VSCR_PUBLIC bool
vscr_ratchet_session_is_initiator(vscr_ratchet_session_t *self);

//
//  Returns flag that indicates if session is post-quantum
//
VSCR_PUBLIC bool
vscr_ratchet_session_is_pqc_enabled(vscr_ratchet_session_t *self);

//
//  Returns true if at least 1 response was successfully decrypted, false - otherwise
//
VSCR_PUBLIC bool
vscr_ratchet_session_received_first_response(vscr_ratchet_session_t *self);

//
//  Returns true if receiver had one time public key
//
VSCR_PUBLIC bool
vscr_ratchet_session_receiver_has_one_time_public_key(vscr_ratchet_session_t *self);

//
//  Encrypts data
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_session_encrypt(vscr_ratchet_session_t *self, vsc_data_t plain_text, vscr_error_t *error);

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCR_PUBLIC size_t
vscr_ratchet_session_decrypt_len(vscr_ratchet_session_t *self, const vscr_ratchet_message_t *message);

//
//  Decrypts message
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_decrypt(vscr_ratchet_session_t *self, const vscr_ratchet_message_t *message,
        vsc_buffer_t *plain_text) VSCR_NODISCARD;

//
//  Serializes session to buffer
//
VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_session_serialize(vscr_ratchet_session_t *self);

//
//  Deserializes session from buffer.
//  NOTE: Deserialized session needs dependencies to be set. Check setup defaults
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_deserialize(vsc_data_t input, vscr_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_SESSION_H_INCLUDED
//  @end
