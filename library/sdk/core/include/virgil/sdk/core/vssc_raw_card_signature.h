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
//  Represent signature of "raw card content" snapshot.
// --------------------------------------------------------------------------

#ifndef VSSC_RAW_CARD_SIGNATURE_H_INCLUDED
#define VSSC_RAW_CARD_SIGNATURE_H_INCLUDED

#include "vssc_library.h"
#include "vssc_json_object.h"
#include "vssc_error.h"
#include "vssc_raw_card_signature.h"
#include "vssc_json_array.h"

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
//  Handle 'raw card signature' context.
//
#ifndef VSSC_RAW_CARD_SIGNATURE_T_DEFINED
#define VSSC_RAW_CARD_SIGNATURE_T_DEFINED
    typedef struct vssc_raw_card_signature_t vssc_raw_card_signature_t;
#endif // VSSC_RAW_CARD_SIGNATURE_T_DEFINED

//
//  Return size of 'vssc_raw_card_signature_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_signature_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init(vssc_raw_card_signature_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_signature_cleanup(vssc_raw_card_signature_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new(void);

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init_with_signature(vssc_raw_card_signature_t *self, vsc_str_t signer_id, vsc_data_t signature);

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_signature(vsc_str_t signer_id, vsc_data_t signature);

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PRIVATE void
vssc_raw_card_signature_init_with_signature_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref);

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PRIVATE vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_signature_disown(vsc_str_t signer_id, vsc_buffer_t **signature_ref);

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init_with_extra_fields(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature, const vssc_json_object_t *extra_fields);

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_extra_fields(vsc_str_t signer_id, vsc_data_t signature,
        const vssc_json_object_t *extra_fields);

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PRIVATE void
vssc_raw_card_signature_init_with_extra_fields_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vssc_json_object_t **extra_fields_ref);

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PRIVATE vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_extra_fields_disown(vsc_str_t signer_id, vsc_buffer_t **signature_ref,
        vssc_json_object_t **extra_fields_ref);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_signature_delete(const vssc_raw_card_signature_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_signature_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_signature_destroy(vssc_raw_card_signature_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_shallow_copy(vssc_raw_card_signature_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_raw_card_signature_t *
vssc_raw_card_signature_shallow_copy_const(const vssc_raw_card_signature_t *self);

//
//  Return identifier of signer.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_signature_signer_id(const vssc_raw_card_signature_t *self);

//
//  Return signature.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_signature_signature(const vssc_raw_card_signature_t *self);

//
//  Return snaphot of additional data.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_signature_snapshot(const vssc_raw_card_signature_t *self);

//
//  Return signed extra fields.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_raw_card_signature_extra_fields(const vssc_raw_card_signature_t *self);

//
//  Create raw card signature from JSON representation.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_import_from_json(const vssc_json_object_t *json, vssc_error_t *error);

//
//  Export Raw Card Signature as JSON.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_raw_card_signature_export_as_json(const vssc_raw_card_signature_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_RAW_CARD_SIGNATURE_H_INCLUDED
//  @end
