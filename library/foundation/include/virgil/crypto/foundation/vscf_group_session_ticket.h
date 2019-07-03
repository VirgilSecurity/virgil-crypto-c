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
//  Group ticket used to start group session, remove participants or proactive to rotate encryption key.
// --------------------------------------------------------------------------

#ifndef VSCF_GROUP_SESSION_TICKET_H_INCLUDED
#define VSCF_GROUP_SESSION_TICKET_H_INCLUDED

#include "vscf_library.h"
#include "vscf_group_session_message.h"
#include "vscf_group_session_message.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
//  Handle 'group session ticket' context.
//
typedef struct vscf_group_session_ticket_t vscf_group_session_ticket_t;

//
//  Return size of 'vscf_group_session_ticket_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_ticket_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_ticket_init(vscf_group_session_ticket_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_ticket_cleanup(vscf_group_session_ticket_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_ticket_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_ticket_delete(vscf_group_session_ticket_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_ticket_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_ticket_destroy(vscf_group_session_ticket_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_ticket_shallow_copy(vscf_group_session_ticket_t *self);

//
//  Random used to generate keys
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_group_session_ticket_use_rng(vscf_group_session_ticket_t *self, vscf_impl_t *rng);

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_group_session_ticket_take_rng(vscf_group_session_ticket_t *self, vscf_impl_t *rng);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_group_session_ticket_release_rng(vscf_group_session_ticket_t *self);

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_ticket_setup_defaults(vscf_group_session_ticket_t *self) VSCF_NODISCARD;

//
//  Set this ticket to start new group session.
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_ticket_setup_ticket_as_new(vscf_group_session_ticket_t *self, vsc_data_t session_id) VSCF_NODISCARD;

//
//  Returns message that should be sent to all participants using secure channel.
//
VSCF_PUBLIC const vscf_group_session_message_t *
vscf_group_session_ticket_get_ticket_message(const vscf_group_session_ticket_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_GROUP_SESSION_TICKET_H_INCLUDED
//  @end
