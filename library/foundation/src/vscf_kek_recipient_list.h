//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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

#ifndef VSCF_KEK_RECIPIENT_LIST_H_INCLUDED
#define VSCF_KEK_RECIPIENT_LIST_H_INCLUDED

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#endif

// clang-format on
//  @end

//  @generated_header_includes
// --------------------------------------------------------------------------
// clang-format off
//  Generated header includes start.
// --------------------------------------------------------------------------

#include "vscf_library.h"
#include "vscf_impl.h"

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
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
//  Handle 'kek recipient list' context.
//
typedef struct vscf_kek_recipient_list_t vscf_kek_recipient_list_t;

//
//  Return size of 'vscf_kek_recipient_list_t'.
//
VSCF_PUBLIC size_t
vscf_kek_recipient_list_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_kek_recipient_list_init(vscf_kek_recipient_list_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_kek_recipient_list_cleanup(vscf_kek_recipient_list_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_kek_recipient_list_t *
vscf_kek_recipient_list_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_kek_recipient_list_delete(vscf_kek_recipient_list_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_kek_recipient_list_new ()'.
//
VSCF_PUBLIC void
vscf_kek_recipient_list_destroy(vscf_kek_recipient_list_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_kek_recipient_list_t *
vscf_kek_recipient_list_shallow_copy(vscf_kek_recipient_list_t *self);

//
//  Add new item to the list.
//
VSCF_PUBLIC void
vscf_kek_recipient_list_add(vscf_kek_recipient_list_t *self, vsc_data_t kek_id, vsc_data_t kek, vscf_impl_t *key_wrap);

//
//  Return true if given list has kek recipient.
//
VSCF_PUBLIC bool
vscf_kek_recipient_list_has_kek_recipient(const vscf_kek_recipient_list_t *self);

//
//  Return KEK identifier.
//
VSCF_PUBLIC vsc_data_t
vscf_kek_recipient_list_kek_id(const vscf_kek_recipient_list_t *self);

//
//  Return KEK bytes.
//
VSCF_PUBLIC vsc_data_t
vscf_kek_recipient_list_kek(const vscf_kek_recipient_list_t *self);

//
//  Return key wrap implementation.
//
VSCF_PUBLIC vscf_impl_t *
vscf_kek_recipient_list_key_wrap(const vscf_kek_recipient_list_t *self);

//
//  Return true if list has next item.
//
VSCF_PUBLIC bool
vscf_kek_recipient_list_has_next(const vscf_kek_recipient_list_t *self);

//
//  Return next list node if exists, or NULL otherwise.
//
VSCF_PUBLIC const vscf_kek_recipient_list_t *
vscf_kek_recipient_list_next(const vscf_kek_recipient_list_t *self);

//
//  Return true if list has previous item.
//
VSCF_PUBLIC bool
vscf_kek_recipient_list_has_prev(const vscf_kek_recipient_list_t *self);

//
//  Return previous list node if exists, or NULL otherwise.
//
VSCF_PUBLIC const vscf_kek_recipient_list_t *
vscf_kek_recipient_list_prev(const vscf_kek_recipient_list_t *self);

// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

#ifdef __cplusplus
}
#endif

//  @footer
#endif // VSCF_KEK_RECIPIENT_LIST_H_INCLUDED
//  @end
