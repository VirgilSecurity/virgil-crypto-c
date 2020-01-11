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
//  Handles a list of signers defined by id and private key.
// --------------------------------------------------------------------------

#ifndef VSCF_SIGNER_LIST_H_INCLUDED
#define VSCF_SIGNER_LIST_H_INCLUDED

#include "vscf_library.h"
#include "vscf_signer_list.h"
#include "vscf_impl.h"

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
//  Handle 'signer list' context.
//
typedef struct vscf_signer_list_t vscf_signer_list_t;

//
//  Return size of 'vscf_signer_list_t'.
//
VSCF_PUBLIC size_t
vscf_signer_list_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_signer_list_init(vscf_signer_list_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_signer_list_cleanup(vscf_signer_list_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_signer_list_t *
vscf_signer_list_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_signer_list_delete(vscf_signer_list_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_signer_list_new ()'.
//
VSCF_PUBLIC void
vscf_signer_list_destroy(vscf_signer_list_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_signer_list_t *
vscf_signer_list_shallow_copy(vscf_signer_list_t *self);

//
//  Add new item to the list.
//  Note, ownership is transfered.
//
VSCF_PUBLIC void
vscf_signer_list_add(vscf_signer_list_t *self, vsc_data_t signer_id, vscf_impl_t *signer_private_key);

//
//  Remove all items.
//
VSCF_PUBLIC void
vscf_signer_list_clear(vscf_signer_list_t *self);

//
//  Return true if given list has signer.
//
VSCF_PUBLIC bool
vscf_signer_list_has_signer(const vscf_signer_list_t *self);

//
//  Return signer identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_signer_list_signer_id(const vscf_signer_list_t *self);

//
//  Return signer private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_signer_list_signer_private_key(const vscf_signer_list_t *self);

//
//  Return true if list has next item.
//
VSCF_PUBLIC bool
vscf_signer_list_has_next(const vscf_signer_list_t *self);

//
//  Return next list node if exists, or NULL otherwise.
//
VSCF_PUBLIC const vscf_signer_list_t *
vscf_signer_list_next(const vscf_signer_list_t *self);

//
//  Return true if list has previous item.
//
VSCF_PUBLIC bool
vscf_signer_list_has_prev(const vscf_signer_list_t *self);

//
//  Return previous list node if exists, or NULL otherwise.
//
VSCF_PUBLIC const vscf_signer_list_t *
vscf_signer_list_prev(const vscf_signer_list_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SIGNER_LIST_H_INCLUDED
//  @end
