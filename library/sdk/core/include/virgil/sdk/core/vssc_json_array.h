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
//  Minimal JSON array.
//  Currently only objects array are supported
// --------------------------------------------------------------------------

#ifndef VSSC_JSON_ARRAY_H_INCLUDED
#define VSSC_JSON_ARRAY_H_INCLUDED

#include "vssc_library.h"
#include "vssc_error.h"
#include "vssc_string_list.h"
#include "vssc_number_list.h"

#if !VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
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
//  Handle 'json array' context.
//
#ifndef VSSC_JSON_ARRAY_T_DEFINED
#define VSSC_JSON_ARRAY_T_DEFINED
    typedef struct vssc_json_array_t vssc_json_array_t;
#endif // VSSC_JSON_ARRAY_T_DEFINED

//
//  Forward declaration.
//
#ifndef VSSC_JSON_OBJECT_T_DEFINED
#define VSSC_JSON_OBJECT_T_DEFINED
    typedef struct vssc_json_object_t vssc_json_object_t;
#endif // VSSC_JSON_OBJECT_T_DEFINED

//
//  Return size of 'vssc_json_array_t'.
//
VSSC_PUBLIC size_t
vssc_json_array_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_json_array_init(vssc_json_array_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_json_array_cleanup(vssc_json_array_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_json_array_delete(const vssc_json_array_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_json_array_new ()'.
//
VSSC_PUBLIC void
vssc_json_array_destroy(vssc_json_array_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_shallow_copy(vssc_json_array_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_json_array_t *
vssc_json_array_shallow_copy_const(const vssc_json_array_t *self);

//
//  Return how many objects an array handles.
//
VSSC_PUBLIC size_t
vssc_json_array_count(const vssc_json_array_t *self);

//
//  Add object value .
//
VSSC_PUBLIC void
vssc_json_array_add_object_value(vssc_json_array_t *self, const vssc_json_object_t *value);

//
//  Return a object value for a given index.
//  Check array length before call this method.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_array_get_object_value(const vssc_json_array_t *self, size_t index, vssc_error_t *error);

//
//  Add string value.
//
VSSC_PUBLIC void
vssc_json_array_add_string_value(vssc_json_array_t *self, vsc_str_t value);

//
//  Return a string value for a given index.
//  Check array length before call this method.
//
VSSC_PUBLIC vsc_str_t
vssc_json_array_get_string_value(const vssc_json_array_t *self, size_t index, vssc_error_t *error);

//
//  Add string values from the given list.
//
VSSC_PUBLIC void
vssc_json_array_add_string_values(vssc_json_array_t *self, const vssc_string_list_t *string_values);

//
//  Return string values as list.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_json_array_get_string_values(const vssc_json_array_t *self, vssc_error_t *error);

//
//  Add number value.
//
VSSC_PUBLIC void
vssc_json_array_add_number_value(vssc_json_array_t *self, size_t value);

//
//  Return a number value for a given index.
//  Check array length before call this method.
//
VSSC_PUBLIC size_t
vssc_json_array_get_number_value(const vssc_json_array_t *self, size_t index, vssc_error_t *error);

//
//  Add number values from the given list.
//
VSSC_PUBLIC void
vssc_json_array_add_number_values(vssc_json_array_t *self, const vssc_number_list_t *number_values);

//
//  Return number values as list.
//
VSSC_PUBLIC vssc_number_list_t *
vssc_json_array_get_number_values(const vssc_json_array_t *self, vssc_error_t *error);

//
//  Return JSON body as string.
//
VSSC_PUBLIC vsc_str_t
vssc_json_array_as_str(const vssc_json_array_t *self);

//
//  Parse a given JSON string.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_parse(vsc_str_t json, vssc_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSC_JSON_ARRAY_H_INCLUDED
//  @end
