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


//  @description
// --------------------------------------------------------------------------
//  Represent Virgil Card.
//
//  Virgil Card is a central entity of Virgil Cards Service.
// --------------------------------------------------------------------------

#ifndef VSSC_CARD_H_INCLUDED
#define VSSC_CARD_H_INCLUDED

#include "vssc_library.h"
#include "vssc_raw_card.h"
#include "vssc_raw_card_signature_list.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#   include <VSCCommon/vsc_data.h>
#endif

#if VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'card' context.
//
#ifndef VSSC_CARD_T_DEFINED
#define VSSC_CARD_T_DEFINED
    typedef struct vssc_card_t vssc_card_t;
#endif // VSSC_CARD_T_DEFINED

//
//  Return size of 'vssc_card_t'.
//
VSSC_PUBLIC size_t
vssc_card_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_init(vssc_card_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_cleanup(vssc_card_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create Virgil Card with mandatory properties.
//
VSSC_PUBLIC void
vssc_card_init_with(vssc_card_t *self, const vssc_raw_card_t *raw_card, vsc_data_t public_key_id,
        const vscf_impl_t *public_key);

//
//  Allocate class context and perform it's initialization.
//  Create Virgil Card with mandatory properties.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_new_with(const vssc_raw_card_t *raw_card, vsc_data_t public_key_id, const vscf_impl_t *public_key);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_delete(const vssc_card_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_new ()'.
//
VSSC_PUBLIC void
vssc_card_destroy(vssc_card_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_shallow_copy(vssc_card_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_shallow_copy_const(const vssc_card_t *self);

//
//  Set previous Card.
//
VSSC_PUBLIC void
vssc_card_set_previous_card(vssc_card_t *self, const vssc_card_t *previous_card);

//
//  Set previous Card.
//
VSSC_PRIVATE void
vssc_card_set_previous_card_disown(vssc_card_t *self, vssc_card_t **previous_card_ref);

//
//  Return Card unique identifier.
//
VSSC_PUBLIC vsc_str_t
vssc_card_identifier(const vssc_card_t *self);

//
//  Return Card identity.
//
VSSC_PUBLIC vsc_str_t
vssc_card_identity(const vssc_card_t *self);

//
//  Return Card public key.
//
VSSC_PUBLIC const vscf_impl_t *
vssc_card_public_key(const vssc_card_t *self);

//
//  Return Card public key identifier.
//
VSSC_PUBLIC vsc_data_t
vssc_card_public_key_id(const vssc_card_t *self);

//
//  Return Card version.
//
VSSC_PUBLIC vsc_str_t
vssc_card_version(const vssc_card_t *self);

//
//  Return timestamp of Card creation.
//
VSSC_PUBLIC size_t
vssc_card_created_at(const vssc_card_t *self);

//
//  Return Card content snapshot.
//
VSSC_PUBLIC vsc_data_t
vssc_card_content_snapshot(const vssc_card_t *self);

//
//  Return whether Card is outdated or not.
//
VSSC_PUBLIC bool
vssc_card_is_outdated(const vssc_card_t *self);

//
//  Return identifier of previous card if exists.
//
VSSC_PUBLIC vsc_str_t
vssc_card_previous_card_id(const vssc_card_t *self);

//
//  Return whether previous card exists or not.
//
VSSC_PUBLIC bool
vssc_card_has_previous_card(const vssc_card_t *self);

//
//  Return previous card if exists, NULL otherwise.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_previous_card(const vssc_card_t *self);

//
//  Return Card signatures,
//
VSSC_PUBLIC const vssc_raw_card_signature_list_t *
vssc_card_signatures(const vssc_card_t *self);

//
//  Return raw card.
//
VSSC_PUBLIC const vssc_raw_card_t *
vssc_card_get_raw_card(const vssc_card_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_CARD_H_INCLUDED
//  @end
