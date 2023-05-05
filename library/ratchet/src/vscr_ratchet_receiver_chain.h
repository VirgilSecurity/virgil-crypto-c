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

#ifndef VSCR_RATCHET_RECEIVER_CHAIN_H_INCLUDED
#define VSCR_RATCHET_RECEIVER_CHAIN_H_INCLUDED

#include "vscr_library.h"
#include "vscr_atomic.h"
#include "vscr_ratchet_pb_utils.h"
#include "vscr_ratchet_typedefs.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_status.h"

#include <vscr_RatchetSession.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>

#if !VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#   include <virgil/crypto/foundation/vscf_round5.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
#   include <VSCFoundation/vscf_round5.h>
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
//  Handle 'ratchet receiver chain' context.
//
typedef struct vscr_ratchet_receiver_chain_t vscr_ratchet_receiver_chain_t;
struct vscr_ratchet_receiver_chain_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    VSCR_ATOMIC size_t refcnt;

    vscr_ratchet_key_id_t public_key_id;

    vscr_ratchet_public_key_t public_key_first;

    vscf_impl_t *public_key_second;

    vscr_ratchet_chain_key_t chain_key;
};

//
//  Return size of 'vscr_ratchet_receiver_chain_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_receiver_chain_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_init(vscr_ratchet_receiver_chain_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_cleanup(vscr_ratchet_receiver_chain_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chain_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_delete(vscr_ratchet_receiver_chain_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_receiver_chain_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_destroy(vscr_ratchet_receiver_chain_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chain_shallow_copy(vscr_ratchet_receiver_chain_t *self);

VSCR_PUBLIC void
vscr_ratchet_receiver_chain_serialize(const vscr_ratchet_receiver_chain_t *self, vscr_ReceiverChain *receiver_chain_pb);

VSCR_PUBLIC vscr_status_t
vscr_ratchet_receiver_chain_deserialize(const vscr_ReceiverChain *receiver_chain_pb,
        vscr_ratchet_receiver_chain_t *receiver_chain, vscf_round5_t *round5) VSCR_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_RECEIVER_CHAIN_H_INCLUDED
//  @end
