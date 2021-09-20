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
//  Represent model in binary form which can have signatures and corresponds to Virgil Cards Service model.
// --------------------------------------------------------------------------

#ifndef VSSC_RAW_CARD_H_INCLUDED
#define VSSC_RAW_CARD_H_INCLUDED

#include "vssc_library.h"
#include "vssc_json_array.h"
#include "vssc_raw_card_signature_list.h"
#include "vssc_error.h"
#include "vssc_raw_card_signature.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_str.h>
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
//  Handle 'raw card' context.
//
#ifndef VSSC_RAW_CARD_T_DEFINED
#define VSSC_RAW_CARD_T_DEFINED
    typedef struct vssc_raw_card_t vssc_raw_card_t;
#endif // VSSC_RAW_CARD_T_DEFINED

//
//  Return size of 'vssc_raw_card_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_init(vssc_raw_card_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_cleanup(vssc_raw_card_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create raw card with mandatory info.
//
VSSC_PUBLIC void
vssc_raw_card_init_with(vssc_raw_card_t *self, vsc_str_t identity, vsc_data_t public_key, size_t created_at);

//
//  Allocate class context and perform it's initialization.
//  Create raw card with mandatory info.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_new_with(vsc_str_t identity, vsc_data_t public_key, size_t created_at);

//
//  Perform initialization of pre-allocated context.
//  Create raw card with mandatory info.
//
VSSC_PRIVATE void
vssc_raw_card_init_with_disown(vssc_raw_card_t *self, vsc_str_t identity, vsc_buffer_t **public_key_ref,
        size_t created_at);

//
//  Allocate class context and perform it's initialization.
//  Create raw card with mandatory info.
//
VSSC_PRIVATE vssc_raw_card_t *
vssc_raw_card_new_with_disown(vsc_str_t identity, vsc_buffer_t **public_key_ref, size_t created_at);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_delete(const vssc_raw_card_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_destroy(vssc_raw_card_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_shallow_copy(vssc_raw_card_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_raw_card_t *
vssc_raw_card_shallow_copy_const(const vssc_raw_card_t *self);

//
//  Create raw card from JSON representation.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_import_from_json(const vssc_json_object_t *json, vssc_error_t *error);

//
//  Create raw card from JSON string representation.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_import_from_json_str(vsc_str_t str, vssc_error_t *error);

//
//  Export Raw Card as JSON.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_raw_card_export_as_json(const vssc_raw_card_t *self);

//
//  Set optional previous card identifier.
//
//  Note, previous card identity and the current one should be the same.
//
VSSC_PUBLIC void
vssc_raw_card_set_previous_card_id(vssc_raw_card_t *self, vsc_str_t previous_card_id);

//
//  Set optional card type.
//
VSSC_PUBLIC void
vssc_raw_card_set_card_type(vssc_raw_card_t *self, vsc_str_t card_type);

//
//  Add new signature.
//
VSSC_PUBLIC void
vssc_raw_card_add_signature(vssc_raw_card_t *self, const vssc_raw_card_signature_t *signature);

//
//  Add new signature.
//
VSSC_PRIVATE void
vssc_raw_card_add_signature_disown(vssc_raw_card_t *self, vssc_raw_card_signature_t **signature_ref);

//
//  Set whether a Card is outdated or not.
//
VSSC_PUBLIC void
vssc_raw_card_set_is_outdated(vssc_raw_card_t *self, bool is_outdated);

//
//  Return version of Card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_version(const vssc_raw_card_t *self);

//
//  Return identity of Card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_identity(const vssc_raw_card_t *self);

//
//  Return Public Key data of Card.
//
//  Note, public key can be empty.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_public_key(const vssc_raw_card_t *self);

//
//  Return date of Card creation.
//
VSSC_PUBLIC size_t
vssc_raw_card_created_at(const vssc_raw_card_t *self);

//
//  Return whether Card is outdated or not.
//
VSSC_PUBLIC bool
vssc_raw_card_is_outdated(const vssc_raw_card_t *self);

//
//  Return identifier of previous Card with same identity.
//
//  Note, return empty string if there is no previous card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_previous_card_id(const vssc_raw_card_t *self);

//
//  Return Card's content snapshot.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_content_snapshot(const vssc_raw_card_t *self);

//
//  Return Card's signatures.
//
VSSC_PUBLIC const vssc_raw_card_signature_list_t *
vssc_raw_card_signatures(const vssc_raw_card_t *self);

//
//  This method invalidates content snapshot.
//  It should be called when content is modified.
//
VSSC_PUBLIC void
vssc_raw_card_invalidate_content_snapshot(vssc_raw_card_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_RAW_CARD_H_INCLUDED
//  @end
