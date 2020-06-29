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
//  Class that handles JWT Header.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_jwt_header.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_jwt_header_defs.h"
#include "vssc_base64_url.h"
#include "vssc_json_array.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_header_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_header_init_ctx(vssc_jwt_header_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_header_cleanup_ctx(vssc_jwt_header_t *self);

//
//  Create JWT Header with application key identifier.
//
static void
vssc_jwt_header_init_ctx_with_app_key_id(vssc_jwt_header_t *self, vsc_str_t app_key_id);

//
//  Perform initialization of pre-allocated context.
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_header_init_with_json_object(vssc_jwt_header_t *self, vssc_json_object_t **json_obj_ref);

//
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_header_init_ctx_with_json_object(vssc_jwt_header_t *self, vssc_json_object_t **json_obj_ref);

//
//  Allocate class context and perform it's initialization.
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static vssc_jwt_header_t *
vssc_jwt_header_new_with_json_object(vssc_json_object_t **json_obj_ref);

//
//  JSON key of JWT signature algorithm.
//
static const char k_json_key_app_key_id_chars[] = "kid";

//
//  JSON key of JWT signature algorithm.
//
static const vsc_str_t k_json_key_app_key_id = {
    k_json_key_app_key_id_chars,
    sizeof(k_json_key_app_key_id_chars) - 1
};

//
//  JSON key of JWT signature algorithm.
//
static const char k_json_key_signature_algorithm_chars[] = "alg";

//
//  JSON key of JWT signature algorithm.
//
static const vsc_str_t k_json_key_signature_algorithm = {
    k_json_key_signature_algorithm_chars,
    sizeof(k_json_key_signature_algorithm_chars) - 1
};

//
//  JSON key of JWT type.
//
static const char k_json_key_type_chars[] = "typ";

//
//  JSON key of JWT type.
//
static const vsc_str_t k_json_key_type = {
    k_json_key_type_chars,
    sizeof(k_json_key_type_chars) - 1
};

//
//  JSON key of JWT content type.
//
static const char k_json_key_content_type_chars[] = "cty";

//
//  JSON key of JWT content type.
//
static const vsc_str_t k_json_key_content_type = {
    k_json_key_content_type_chars,
    sizeof(k_json_key_content_type_chars) - 1
};

//
//  Represents default JWT signature algorithm.
//
static const char k_signature_algorithm_default_chars[] = "VEDS512";

//
//  Represents default JWT signature algorithm.
//
static const vsc_str_t k_signature_algorithm_default = {
    k_signature_algorithm_default_chars,
    sizeof(k_signature_algorithm_default_chars) - 1
};

//
//  Represents default JWT token type.
//
static const char k_type_default_chars[] = "JWT";

//
//  Represents default JWT token type.
//
static const vsc_str_t k_type_default = {
    k_type_default_chars,
    sizeof(k_type_default_chars) - 1
};

//
//  Represents default JWT content type.
//
static const char k_content_type_default_chars[] = "virgil-jwt;v=1";

//
//  Represents default JWT content type.
//
static const vsc_str_t k_content_type_default = {
    k_content_type_default_chars,
    sizeof(k_content_type_default_chars) - 1
};

//
//  Return size of 'vssc_jwt_header_t'.
//
VSSC_PUBLIC size_t
vssc_jwt_header_ctx_size(void) {

    return sizeof(vssc_jwt_header_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_jwt_header_init(vssc_jwt_header_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_header_t));

    self->refcnt = 1;

    vssc_jwt_header_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_jwt_header_cleanup(vssc_jwt_header_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_jwt_header_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_jwt_header_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_jwt_header_t *
vssc_jwt_header_new(void) {

    vssc_jwt_header_t *self = (vssc_jwt_header_t *) vssc_alloc(sizeof (vssc_jwt_header_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_header_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create JWT Header with application key identifier.
//
VSSC_PUBLIC void
vssc_jwt_header_init_with_app_key_id(vssc_jwt_header_t *self, vsc_str_t app_key_id) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_header_t));

    self->refcnt = 1;

    vssc_jwt_header_init_ctx_with_app_key_id(self, app_key_id);
}

//
//  Allocate class context and perform it's initialization.
//  Create JWT Header with application key identifier.
//
VSSC_PUBLIC vssc_jwt_header_t *
vssc_jwt_header_new_with_app_key_id(vsc_str_t app_key_id) {

    vssc_jwt_header_t *self = (vssc_jwt_header_t *) vssc_alloc(sizeof (vssc_jwt_header_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_header_init_with_app_key_id(self, app_key_id);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_header_init_with_json_object(vssc_jwt_header_t *self, vssc_json_object_t **json_obj_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_header_t));

    self->refcnt = 1;

    vssc_jwt_header_init_ctx_with_json_object(self, json_obj_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static vssc_jwt_header_t *
vssc_jwt_header_new_with_json_object(vssc_json_object_t **json_obj_ref) {

    vssc_jwt_header_t *self = (vssc_jwt_header_t *) vssc_alloc(sizeof (vssc_jwt_header_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_header_init_with_json_object(self, json_obj_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_jwt_header_delete(const vssc_jwt_header_t *self) {

    vssc_jwt_header_t *local_self = (vssc_jwt_header_t *)self;

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

    vssc_jwt_header_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_jwt_header_new ()'.
//
VSSC_PUBLIC void
vssc_jwt_header_destroy(vssc_jwt_header_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_jwt_header_t *self = *self_ref;
    *self_ref = NULL;

    vssc_jwt_header_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_jwt_header_t *
vssc_jwt_header_shallow_copy(vssc_jwt_header_t *self) {

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
VSSC_PUBLIC const vssc_jwt_header_t *
vssc_jwt_header_shallow_copy_const(const vssc_jwt_header_t *self) {

    return vssc_jwt_header_shallow_copy((vssc_jwt_header_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_header_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_header_init_ctx(vssc_jwt_header_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_header_cleanup_ctx(vssc_jwt_header_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_object_destroy(&self->json_obj);
}

//
//  Create JWT Header with application key identifier.
//
static void
vssc_jwt_header_init_ctx_with_app_key_id(vssc_jwt_header_t *self, vsc_str_t app_key_id) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(app_key_id));

    self->json_obj = vssc_json_object_new();
    vssc_json_object_add_string_value(self->json_obj, k_json_key_app_key_id, app_key_id);
    vssc_json_object_add_string_value(self->json_obj, k_json_key_content_type, k_content_type_default);
    vssc_json_object_add_string_value(self->json_obj, k_json_key_type, k_type_default);
    vssc_json_object_add_string_value(self->json_obj, k_json_key_signature_algorithm, k_signature_algorithm_default);
}

//
//  Create JWT Header defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_header_init_ctx_with_json_object(vssc_jwt_header_t *self, vssc_json_object_t **json_obj_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(json_obj_ref);

    self->json_obj = *json_obj_ref;
    *json_obj_ref = NULL;
}

//
//  Parse JWT Header from a string representation.
//
VSSC_PUBLIC vssc_jwt_header_t *
vssc_jwt_header_parse(vsc_str_t header_str, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid(header_str));

    //
    //  Declare vars.
    //
    vssc_error_t inner_error;
    vssc_error_reset(&inner_error);

    const size_t header_json_str_len = vssc_base64_url_decoded_len(header_str.len);
    vsc_buffer_t *header_json_buff = vsc_buffer_new_with_capacity(header_json_str_len);

    vssc_json_object_t *json_obj = NULL;

    inner_error.status = vssc_base64_url_decode(header_str, header_json_buff);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    json_obj = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(header_json_buff)), &inner_error);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    //
    //  Check fields.
    //
    vsc_str_t app_key_id = vssc_json_object_get_string_value(json_obj, k_json_key_app_key_id, &inner_error);
    if (vssc_error_has_error(&inner_error) || vsc_str_is_empty(app_key_id)) {
        goto fail;
    }


    vsc_str_t type = vssc_json_object_get_string_value(json_obj, k_json_key_type, &inner_error);
    if (vssc_error_has_error(&inner_error) || !vsc_str_equal(k_type_default, type)) {
        goto fail;
    }


    vsc_str_t content_type = vssc_json_object_get_string_value(json_obj, k_json_key_content_type, &inner_error);
    if (vssc_error_has_error(&inner_error) || !vsc_str_equal(k_content_type_default, content_type)) {
        goto fail;
    }


    vsc_str_t signature_algorithm =
            vssc_json_object_get_string_value(json_obj, k_json_key_signature_algorithm, &inner_error);
    if (vssc_error_has_error(&inner_error) || !vsc_str_equal(k_signature_algorithm_default, signature_algorithm)) {
        goto fail;
    }

    goto succ;

fail:

    vssc_json_object_destroy(&json_obj);

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);

succ:
    vsc_buffer_destroy(&header_json_buff);

    if (json_obj) {
        return vssc_jwt_header_new_with_json_object(&json_obj);
    } else {
        return NULL;
    }
}

//
//  Return lengh for buffer that can hold JWT Header string representation.
//
VSSC_PUBLIC size_t
vssc_jwt_header_as_string_len(const vssc_jwt_header_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_t json_str = vssc_jwt_header_as_json_string(self);

    return vssc_base64_url_encoded_len(json_str.len);
}

//
//  Return JWT Header string representation.
//  Representations is base64url.encode(json).
//
VSSC_PUBLIC void
vssc_jwt_header_as_string(const vssc_jwt_header_t *self, vsc_str_buffer_t *str_buffer) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_buffer_is_valid(str_buffer));
    VSSC_ASSERT(vsc_str_buffer_unused_len(str_buffer) >= vssc_jwt_header_as_string_len(self));

    vsc_str_t json_str = vssc_jwt_header_as_json_string(self);

    vssc_base64_url_encode(vsc_str_as_data(json_str), str_buffer);
}

//
//  Return JWT Header as JSON string.
//
VSSC_PRIVATE vsc_str_t
vssc_jwt_header_as_json_string(const vssc_jwt_header_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    return vssc_json_object_as_str(self->json_obj);
}
