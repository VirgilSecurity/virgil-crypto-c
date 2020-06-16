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


//  @description
// --------------------------------------------------------------------------
//  Minimal JSON array.
//  Currently only objects array are supported
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_json_array.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_json_array_private.h"
#include "vssc_json_array_defs.h"
#include "vssc_json_object_defs.h"
#include "vssc_json_object_private.h"

#include <json-c/json.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_json_array_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_json_array_init_ctx(vssc_json_array_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_json_array_cleanup_ctx(vssc_json_array_t *self);

//
//  Perform initialization of pre-allocated context.
//  Create with predefined JSON object.
//
static void
vssc_json_array_init_with_json_obj(vssc_json_array_t *self, json_object **json_obj_ref);

//
//  Create with predefined JSON object.
//
static void
vssc_json_array_init_ctx_with_json_obj(vssc_json_array_t *self, json_object **json_obj_ref);

//
//  Allocate class context and perform it's initialization.
//  Create with predefined JSON object.
//
static vssc_json_array_t *
vssc_json_array_new_with_json_obj(json_object **json_obj_ref);

//
//  Return size of 'vssc_json_array_t'.
//
VSSC_PUBLIC size_t
vssc_json_array_ctx_size(void) {

    return sizeof(vssc_json_array_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_json_array_init(vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_json_array_t));

    self->refcnt = 1;

    vssc_json_array_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_json_array_cleanup(vssc_json_array_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_json_array_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_json_array_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_new(void) {

    vssc_json_array_t *self = (vssc_json_array_t *) vssc_alloc(sizeof (vssc_json_array_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_json_array_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create with predefined JSON object.
//
static void
vssc_json_array_init_with_json_obj(vssc_json_array_t *self, json_object **json_obj_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_json_array_t));

    self->refcnt = 1;

    vssc_json_array_init_ctx_with_json_obj(self, json_obj_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create with predefined JSON object.
//
static vssc_json_array_t *
vssc_json_array_new_with_json_obj(json_object **json_obj_ref) {

    vssc_json_array_t *self = (vssc_json_array_t *) vssc_alloc(sizeof (vssc_json_array_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_json_array_init_with_json_obj(self, json_obj_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_json_array_delete(const vssc_json_array_t *self) {

    vssc_json_array_t *local_self = (vssc_json_array_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssc_json_array_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_json_array_new ()'.
//
VSSC_PUBLIC void
vssc_json_array_destroy(vssc_json_array_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_json_array_t *self = *self_ref;
    *self_ref = NULL;

    vssc_json_array_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_shallow_copy(vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_json_array_t *
vssc_json_array_shallow_copy_const(const vssc_json_array_t *self) {

    return vssc_json_array_shallow_copy((vssc_json_array_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_json_array_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_json_array_init_ctx(vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);

    self->json_obj = json_object_new_array();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_json_array_cleanup_ctx(vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);

    json_object_put(self->json_obj);
}

//
//  Create with predefined JSON object.
//
static void
vssc_json_array_init_ctx_with_json_obj(vssc_json_array_t *self, json_object **json_obj_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(json_obj_ref);

    self->json_obj = *json_obj_ref;
    *json_obj_ref = NULL;
}

//
//  Create with predefined JSON object.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_create_with_json_obj(json_object **json_obj_ref) {

    VSSC_ASSERT_REF(json_obj_ref);

    return vssc_json_array_new_with_json_obj(json_obj_ref);
}

//
//  Return array length.
//
VSSC_PUBLIC size_t
vssc_json_array_len(const vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    return json_object_array_length(self->json_obj);
}

//
//  Add object value .
//
VSSC_PUBLIC void
vssc_json_array_add_object_value(vssc_json_array_t *self, const vssc_json_object_t *value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT_PTR(value);
    VSSC_ASSERT_PTR(value->json_obj);

    const int add_result = json_object_array_add(self->json_obj, json_object_get((json_object *)value->json_obj));
    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);
}

//
//  Add object value .
//
VSSC_PRIVATE void
vssc_json_array_add_object_value_disown(vssc_json_array_t *self, vssc_json_object_t **value_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT_REF(value_ref);
    VSSC_ASSERT_PTR((*value_ref)->json_obj);

    const int add_result = json_object_array_add(self->json_obj, json_object_get((*value_ref)->json_obj));
    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);

    vssc_json_object_destroy(value_ref);
}

//
//  Return a object value for a given index.
//  Check array length before call this method.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_array_get_object_value(const vssc_json_array_t *self, size_t index, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    json_object *json_obj = json_object_array_get_idx(self->json_obj, index);
    if (NULL == json_obj || !json_object_is_type(json_obj, json_type_object)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_TYPE_MISMATCH);
        return NULL;
    }

    json_obj = json_object_get(json_obj); // increase ref counter.

    return vssc_json_object_create_with_json_obj(&json_obj);
}

//
//  Add string value.
//
VSSC_PUBLIC void
vssc_json_array_add_string_value(vssc_json_array_t *self, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT(vsc_str_is_valid(value));

    json_object *str_obj = json_object_new_string_len(value.chars, value.len);
    VSSC_ASSERT_ALLOC(str_obj);

    const int add_result = json_object_array_add(self->json_obj, str_obj);

    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);
}

//
//  Return a string value for a given index.
//  Check array length before call this method.
//
VSSC_PUBLIC vsc_str_t
vssc_json_array_get_string_value(const vssc_json_array_t *self, size_t index, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    json_object *str_obj = json_object_array_get_idx(self->json_obj, index);

    if (NULL == str_obj) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_NOT_FOUND);
        return vsc_str_empty();
    }

    if (!json_object_is_type(str_obj, json_type_string)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_TYPE_MISMATCH);
        return vsc_str_empty();
    }

    return vsc_str(json_object_get_string(str_obj), json_object_get_string_len(str_obj));
}

//
//  Return JSON body as string.
//
VSSC_PUBLIC vsc_str_t
vssc_json_array_as_str(const vssc_json_array_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    size_t len = 0;
    const char *chars = json_object_to_json_string_length(self->json_obj, JSON_C_TO_STRING_PLAIN, &len);

    return vsc_str(chars, len);
}

//
//  Parse a given JSON string.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_array_parse(vsc_str_t json, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid(json));

    json_tokener *tokener = json_tokener_new();
    VSSC_ASSERT_ALLOC(tokener);

    json_object *json_obj = json_tokener_parse_ex(tokener, json.chars, json.len);
    json_tokener_free(tokener);

    if (NULL == json_obj) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JSON_FAILED);
        return NULL;
    }

    if (!json_object_is_type(json_obj, json_type_array)) {
        json_object_put(json_obj);
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JSON_FAILED);
        return NULL;
    }

    return vssc_json_array_new_with_json_obj(&json_obj);
}
