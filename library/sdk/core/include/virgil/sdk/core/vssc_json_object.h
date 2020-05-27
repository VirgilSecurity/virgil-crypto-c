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
//  Minimal JSON object.
// --------------------------------------------------------------------------

#ifndef VSSC_JSON_OBJECT_H_INCLUDED
#define VSSC_JSON_OBJECT_H_INCLUDED

#include "vssc_library.h"
#include "vssc_error.h"
#include "vssc_json_object.h"
#include "vssc_status.h"

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
//  Handle 'json object' context.
//
typedef struct vssc_json_object_t vssc_json_object_t;

//
//  Return size of 'vssc_json_object_t'.
//
VSSC_PUBLIC size_t
vssc_json_object_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_json_object_init(vssc_json_object_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_json_object_cleanup(vssc_json_object_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_json_object_delete(vssc_json_object_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_json_object_new ()'.
//
VSSC_PUBLIC void
vssc_json_object_destroy(vssc_json_object_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_shallow_copy(vssc_json_object_t *self);

//
//  Add string value with a given key.
//
VSSC_PUBLIC void
vssc_json_object_add_string_value(vssc_json_object_t *self, vsc_str_t key, vsc_str_t value);

//
//  Return a string value for a given key.
//  Returns error, if given key is not found or type mismatch.
//
VSSC_PUBLIC vsc_str_t
vssc_json_object_get_string_value(const vssc_json_object_t *self, vsc_str_t key, vssc_error_t *error);

//
//  Add binary value with a given key.
//  Given binary value is base64 encoded first
//
VSSC_PUBLIC void
vssc_json_object_add_binary_value(vssc_json_object_t *self, vsc_str_t key, vsc_data_t value);

//
//  Return buffer length required to hold a binary value for a given key.
//  Returns 0, if given key is not found or type mismatch.
//
VSSC_PUBLIC size_t
vssc_json_object_get_binary_value_len(const vssc_json_object_t *self, vsc_str_t key);

//
//  Return a binary value for a given key.
//  Returns error, if given key is not found or type mismatch.
//  Returns error, if base64 decode failed.
//
VSSC_PUBLIC vssc_status_t
vssc_json_object_get_binary_value(const vssc_json_object_t *self, vsc_str_t key, vsc_buffer_t *value) VSSC_NODISCARD;

//
//  Add integer value with a given key.
//
VSSC_PUBLIC void
vssc_json_object_add_int_value(vssc_json_object_t *self, vsc_str_t key, int value);

//
//  Return a integer value for a given key.
//  Returns error, if given key is not found or type mismatch.
//
VSSC_PUBLIC int
vssc_json_object_get_int_value(const vssc_json_object_t *self, vsc_str_t key, vssc_error_t *error);

//
//  Return JSON body as string.
//
VSSC_PUBLIC vsc_str_t
vssc_json_object_as_str(const vssc_json_object_t *self);

//
//  Parse a given JSON string.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_parse(vsc_str_t json, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_JSON_OBJECT_H_INCLUDED
//  @end
