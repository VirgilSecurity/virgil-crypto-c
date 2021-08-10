//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#ifndef VSCF_GROUP_SESSION_EPOCH_NODE_H_INCLUDED
#define VSCF_GROUP_SESSION_EPOCH_NODE_H_INCLUDED

#include "vscf_library.h"
#include "vscf_atomic.h"
#include "vscf_group_session_epoch.h"

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
//  Handle 'group session epoch node' context.
//
#ifndef VSCF_GROUP_SESSION_EPOCH_NODE_T_DEFINED
#define VSCF_GROUP_SESSION_EPOCH_NODE_T_DEFINED
    typedef struct vscf_group_session_epoch_node_t vscf_group_session_epoch_node_t;
#endif // VSCF_GROUP_SESSION_EPOCH_NODE_T_DEFINED
struct vscf_group_session_epoch_node_t {
    //
    //  Function do deallocate self context.
    //
    vscf_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    VSCF_ATOMIC size_t refcnt;

    vscf_group_session_epoch_t *value;
    //
    //  Class specific context.
    //
    vscf_group_session_epoch_node_t *prev;
    //
    //  Class specific context.
    //
    vscf_group_session_epoch_node_t *next;
};

//
//  Return size of 'vscf_group_session_epoch_node_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_epoch_node_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_epoch_node_init(vscf_group_session_epoch_node_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_epoch_node_cleanup(vscf_group_session_epoch_node_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_epoch_node_t *
vscf_group_session_epoch_node_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_epoch_node_delete(const vscf_group_session_epoch_node_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_epoch_node_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_epoch_node_destroy(vscf_group_session_epoch_node_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_epoch_node_t *
vscf_group_session_epoch_node_shallow_copy(vscf_group_session_epoch_node_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_group_session_epoch_node_t *
vscf_group_session_epoch_node_shallow_copy_const(const vscf_group_session_epoch_node_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_GROUP_SESSION_EPOCH_NODE_H_INCLUDED
//  @end
