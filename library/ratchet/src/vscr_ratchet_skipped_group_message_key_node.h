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

#ifndef VSCR_RATCHET_SKIPPED_GROUP_MESSAGE_KEY_NODE_H_INCLUDED
#define VSCR_RATCHET_SKIPPED_GROUP_MESSAGE_KEY_NODE_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_skipped_group_message_key.h"
#include "vscr_ratchet_skipped_group_message_key_node.h"

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
//  Handle 'ratchet skipped group message key node' context.
//
typedef struct vscr_ratchet_skipped_group_message_key_node_t vscr_ratchet_skipped_group_message_key_node_t;
struct vscr_ratchet_skipped_group_message_key_node_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscr_ratchet_skipped_group_message_key_t *value;

    vscr_ratchet_skipped_group_message_key_node_t *next;
};

//
//  Return size of 'vscr_ratchet_skipped_group_message_key_node_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_skipped_group_message_key_node_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_group_message_key_node_init(vscr_ratchet_skipped_group_message_key_node_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_group_message_key_node_cleanup(vscr_ratchet_skipped_group_message_key_node_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_skipped_group_message_key_node_t *
vscr_ratchet_skipped_group_message_key_node_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_group_message_key_node_delete(vscr_ratchet_skipped_group_message_key_node_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_skipped_group_message_key_node_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_group_message_key_node_destroy(vscr_ratchet_skipped_group_message_key_node_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_skipped_group_message_key_node_t *
vscr_ratchet_skipped_group_message_key_node_shallow_copy(vscr_ratchet_skipped_group_message_key_node_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_SKIPPED_GROUP_MESSAGE_KEY_NODE_H_INCLUDED
//  @end
