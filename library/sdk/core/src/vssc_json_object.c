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
//  Minimal JSON object.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_json_object.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_json_object_private.h"
#include "vssc_json_object_defs.h"
#include "vssc_json_array_defs.h"
#include "vssc_json_array_private.h"

#include <json-c/json.h>
#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/foundation/vscf_base64.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_json_object_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_json_object_init_ctx(vssc_json_object_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_json_object_cleanup_ctx(vssc_json_object_t *self);

//
//  Perform initialization of pre-allocated context.
//  Create with predefined JSON object.
//
static void
vssc_json_object_init_with_json_obj(vssc_json_object_t *self, json_object **json_obj_ref);

//
//  Create with predefined JSON object.
//
static void
vssc_json_object_init_ctx_with_json_obj(vssc_json_object_t *self, json_object **json_obj_ref);

//
//  Allocate class context and perform it's initialization.
//  Create with predefined JSON object.
//
static vssc_json_object_t *
vssc_json_object_new_with_json_obj(json_object **json_obj_ref);

//
//  Return size of 'vssc_json_object_t'.
//
VSSC_PUBLIC size_t
vssc_json_object_ctx_size(void) {

    return sizeof(vssc_json_object_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_json_object_init(vssc_json_object_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_json_object_t));

    self->refcnt = 1;

    vssc_json_object_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_json_object_cleanup(vssc_json_object_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_json_object_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_json_object_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_new(void) {

    vssc_json_object_t *self = (vssc_json_object_t *) vssc_alloc(sizeof (vssc_json_object_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_json_object_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create with predefined JSON object.
//
static void
vssc_json_object_init_with_json_obj(vssc_json_object_t *self, json_object **json_obj_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_json_object_t));

    self->refcnt = 1;

    vssc_json_object_init_ctx_with_json_obj(self, json_obj_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create with predefined JSON object.
//
static vssc_json_object_t *
vssc_json_object_new_with_json_obj(json_object **json_obj_ref) {

    vssc_json_object_t *self = (vssc_json_object_t *) vssc_alloc(sizeof (vssc_json_object_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_json_object_init_with_json_obj(self, json_obj_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_json_object_delete(const vssc_json_object_t *self) {

    vssc_json_object_t *local_self = (vssc_json_object_t *)self;

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

    vssc_json_object_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_json_object_new ()'.
//
VSSC_PUBLIC void
vssc_json_object_destroy(vssc_json_object_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_json_object_t *self = *self_ref;
    *self_ref = NULL;

    vssc_json_object_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_shallow_copy(vssc_json_object_t *self) {

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
VSSC_PUBLIC const vssc_json_object_t *
vssc_json_object_shallow_copy_const(const vssc_json_object_t *self) {

    return vssc_json_object_shallow_copy((vssc_json_object_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_json_object_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_json_object_init_ctx(vssc_json_object_t *self) {

    VSSC_ASSERT_PTR(self);

    self->json_obj = json_object_new_object();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_json_object_cleanup_ctx(vssc_json_object_t *self) {

    VSSC_ASSERT_PTR(self);

    json_object_put(self->json_obj);
}

//
//  Create with predefined JSON object.
//
static void
vssc_json_object_init_ctx_with_json_obj(vssc_json_object_t *self, json_object **json_obj_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(json_obj_ref);

    self->json_obj = *json_obj_ref;
    *json_obj_ref = NULL;
}

//
//  Create with predefined JSON object.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_create_with_json_obj(json_object **json_obj_ref) {

    VSSC_ASSERT_REF(json_obj_ref);

    return vssc_json_object_new_with_json_obj(json_obj_ref);
}

//
//  Return true if object has no fields.
//
VSSC_PUBLIC bool
vssc_json_object_is_empty(const vssc_json_object_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    lh_table *ht = json_object_get_object(self->json_obj);

    return 0 == ht->count;
}

//
//  Add string value with a given key.
//
VSSC_PUBLIC void
vssc_json_object_add_string_value(vssc_json_object_t *self, vsc_str_t key, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(value));

    json_object *str_obj = json_object_new_string_len(value.chars, value.len);
    VSSC_ASSERT_ALLOC(str_obj);

    int add_result = 0;
    if (vsc_str_is_null_terminated(key)) {
        add_result = json_object_object_add(self->json_obj, key.chars, str_obj);

    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        add_result = json_object_object_add(self->json_obj, key_nt.chars, str_obj);
        vsc_str_mutable_release(&key_nt);
    }

    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);
}

//
//  Return a string value for a given key.
//  Return error, if given key is not found or type mismatch.
//
VSSC_PUBLIC vsc_str_t
vssc_json_object_get_string_value(const vssc_json_object_t *self, vsc_str_t key, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    json_object *str_obj = NULL;
    json_bool is_found = false;

    if (vsc_str_is_null_terminated(key)) {
        is_found = json_object_object_get_ex(self->json_obj, key.chars, &str_obj);
    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        is_found = json_object_object_get_ex(self->json_obj, key_nt.chars, &str_obj);
        vsc_str_mutable_release(&key_nt);
    }

    if (!is_found) {
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
//  Add binary value with a given key.
//  Given binary value is base64 encoded first
//
VSSC_PUBLIC void
vssc_json_object_add_binary_value(vssc_json_object_t *self, vsc_str_t key, vsc_data_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSC_ASSERT(vsc_data_is_valid(value));

    const size_t base64_len = vscf_base64_encoded_len(value.len);
    vsc_buffer_t *base64_buf = vsc_buffer_new_with_capacity(base64_len);

    vscf_base64_encode(value, base64_buf);

    vssc_json_object_add_string_value(self, key, vsc_str_from_data(vsc_buffer_data(base64_buf)));

    vsc_buffer_destroy(&base64_buf);
}

//
//  Return buffer length required to hold a binary value for a given key.
//  Returns 0, if given key is not found or type mismatch.
//
VSSC_PUBLIC size_t
vssc_json_object_get_binary_value_len(const vssc_json_object_t *self, vsc_str_t key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    vsc_str_t base64_str = vssc_json_object_get_string_value(self, key, NULL);

    return vscf_base64_decoded_len(base64_str.len);
}

//
//  Return a binary value for a given key.
//  Return error, if given key is not found or type mismatch.
//  Return error, if base64 decode failed.
//
VSSC_PUBLIC vssc_status_t
vssc_json_object_get_binary_value(const vssc_json_object_t *self, vsc_str_t key, vsc_buffer_t *value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSC_ASSERT(vsc_buffer_is_valid(value));

    vssc_error_t error;
    vssc_error_reset(&error);

    vsc_str_t base64_str = vssc_json_object_get_string_value(self, key, &error);
    if (vssc_error_has_error(&error)) {
        return vssc_error_status(&error);
    }

    const size_t data_len = vscf_base64_decoded_len(base64_str.len);
    VSSC_ASSERT(vsc_buffer_unused_len(value) >= data_len);

    const vscf_status_t base64_status = vscf_base64_decode(vsc_str_as_data(base64_str), value);

    return (base64_status == vscf_status_SUCCESS) ? vssc_status_SUCCESS : vssc_status_JSON_VALUE_IS_NOT_BASE64;
}

//
//  Add integer value with a given key.
//
VSSC_PUBLIC void
vssc_json_object_add_int_value(vssc_json_object_t *self, vsc_str_t key, int value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    json_object *int_obj = json_object_new_int(value);
    VSSC_ASSERT_ALLOC(int_obj);

    int add_result = 0;
    if (vsc_str_is_null_terminated(key)) {
        add_result = json_object_object_add(self->json_obj, key.chars, int_obj);

    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        add_result = json_object_object_add(self->json_obj, key_nt.chars, int_obj);
        vsc_str_mutable_release(&key_nt);
    }

    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);
}

//
//  Return an integer value for a given key.
//  Return error, if given key is not found or type mismatch.
//
VSSC_PUBLIC int
vssc_json_object_get_int_value(const vssc_json_object_t *self, vsc_str_t key, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    json_object *int_obj = NULL;
    json_bool is_found = false;

    if (vsc_str_is_null_terminated(key)) {
        is_found = json_object_object_get_ex(self->json_obj, key.chars, &int_obj);
    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        is_found = json_object_object_get_ex(self->json_obj, key_nt.chars, &int_obj);
        vsc_str_mutable_release(&key_nt);
    }

    if (!is_found) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_NOT_FOUND);
        return 0;
    }

    if (!json_object_is_type(int_obj, json_type_int)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_TYPE_MISMATCH);
        return 0;
    }

    return json_object_get_int(int_obj);
}

//
//  Add array value with a given key.
//
VSSC_PUBLIC void
vssc_json_object_add_array_value(vssc_json_object_t *self, vsc_str_t key, const vssc_json_array_t *value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT_PTR(value);
    VSSC_ASSERT_PTR(value->json_obj);

    int add_result = 0;
    if (vsc_str_is_null_terminated(key)) {
        add_result = json_object_object_add(self->json_obj, key.chars, json_object_get((json_object *)value->json_obj));

    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        add_result =
                json_object_object_add(self->json_obj, key_nt.chars, json_object_get((json_object *)value->json_obj));
        vsc_str_mutable_release(&key_nt);
    }

    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);
}

//
//  Add array value with a given key.
//
VSSC_PRIVATE void
vssc_json_object_add_array_value_disown(vssc_json_object_t *self, vsc_str_t key, vssc_json_array_t **value_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);
    VSSC_ASSERT_REF(value_ref);
    VSSC_ASSERT_PTR((*value_ref)->json_obj);

    int add_result = 0;
    if (vsc_str_is_null_terminated(key)) {
        add_result = json_object_object_add(self->json_obj, key.chars, json_object_get((*value_ref)->json_obj));

    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        add_result = json_object_object_add(self->json_obj, key_nt.chars, json_object_get((*value_ref)->json_obj));
        vsc_str_mutable_release(&key_nt);
    }

    VSSC_ASSERT_LIBRARY_JSON_C_SUCCESS(add_result);

    vssc_json_array_destroy(value_ref);
}

//
//  Return an array value for a given key.
//  Return error, if given key is not found or type mismatch.
//
VSSC_PUBLIC vssc_json_array_t *
vssc_json_object_get_array_value(const vssc_json_object_t *self, vsc_str_t key, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    json_object *json_obj = NULL;
    json_bool is_found = false;

    if (vsc_str_is_null_terminated(key)) {
        is_found = json_object_object_get_ex(self->json_obj, key.chars, &json_obj);
    } else {
        vsc_str_mutable_t key_nt = vsc_str_mutable_from_str(key);
        is_found = json_object_object_get_ex(self->json_obj, key_nt.chars, &json_obj);
        vsc_str_mutable_release(&key_nt);
    }

    if (!is_found) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_NOT_FOUND);
        return 0;
    }

    if (!json_object_is_type(json_obj, json_type_array)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_JSON_VALUE_TYPE_MISMATCH);
        return 0;
    }


    json_obj = json_object_get(json_obj); // increase ref counter.

    return vssc_json_array_create_with_json_obj(&json_obj);
}

//
//  Return JSON body as string.
//
VSSC_PUBLIC vsc_str_t
vssc_json_object_as_str(const vssc_json_object_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    size_t len = 0;
    const char *chars = json_object_to_json_string_length(self->json_obj, JSON_C_TO_STRING_PLAIN, &len);

    return vsc_str(chars, len);
}

//
//  Parse a given JSON string.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_json_object_parse(vsc_str_t json, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid(json));

    json_tokener *tokener = json_tokener_new();
    VSSC_ASSERT_ALLOC(tokener);

    json_object *json_obj = json_tokener_parse_ex(tokener, json.chars, json.len);
    json_tokener_free(tokener);

    if (NULL == json_obj || !json_object_is_type(json_obj, json_type_object)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JSON_FAILED);
        return NULL;
    }

    return vssc_json_object_new_with_json_obj(&json_obj);
}
