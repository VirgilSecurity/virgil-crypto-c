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
//  Class that handles JWT Payload.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_jwt_payload.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_jwt_payload_defs.h"
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
//  Note, this method is called automatically when method vssc_jwt_payload_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_payload_init_ctx(vssc_jwt_payload_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_payload_cleanup_ctx(vssc_jwt_payload_t *self);

//
//  Create fully defined JWT Payload.
//
static void
vssc_jwt_payload_init_ctx_with_members(vssc_jwt_payload_t *self, vsc_str_t app_id, vsc_str_t identity, size_t issued_at,
        size_t expires_at);

//
//  Perform initialization of pre-allocated context.
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_payload_init_with_json_object(vssc_jwt_payload_t *self, vssc_json_object_t **json_obj_ref);

//
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_payload_init_ctx_with_json_object(vssc_jwt_payload_t *self, vssc_json_object_t **json_obj_ref);

//
//  Allocate class context and perform it's initialization.
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static vssc_jwt_payload_t *
vssc_jwt_payload_new_with_json_object(vssc_json_object_t **json_obj_ref);

//
//  Prefix for JSON value under the key "iss".
//
static const char k_json_value_prefix_app_id_chars[] = "virgil-";

//
//  Prefix for JSON value under the key "iss".
//
static const vsc_str_t k_json_value_prefix_app_id = {
    k_json_value_prefix_app_id_chars,
    sizeof(k_json_value_prefix_app_id_chars) - 1
};

//
//  Prefix for JSON value under the key "sub".
//
static const char k_json_value_prefix_identity_chars[] = "identity-";

//
//  Prefix for JSON value under the key "sub".
//
static const vsc_str_t k_json_value_prefix_identity = {
    k_json_value_prefix_identity_chars,
    sizeof(k_json_value_prefix_identity_chars) - 1
};

//
//  JSON key of application id JWT belongs to.
//
static const char k_json_key_app_id_chars[] = "iss";

//
//  JSON key of application id JWT belongs to.
//
static const vsc_str_t k_json_key_app_id = {
    k_json_key_app_id_chars,
    sizeof(k_json_key_app_id_chars) - 1
};

//
//  JSON key of JWT identity.
//
static const char k_json_key_identity_chars[] = "sub";

//
//  JSON key of JWT identity.
//
static const vsc_str_t k_json_key_identity = {
    k_json_key_identity_chars,
    sizeof(k_json_key_identity_chars) - 1
};

//
//  JSON key of JWT issued at date.
//
static const char k_json_key_issued_at_chars[] = "iat";

//
//  JSON key of JWT issued at date.
//
static const vsc_str_t k_json_key_issued_at = {
    k_json_key_issued_at_chars,
    sizeof(k_json_key_issued_at_chars) - 1
};

//
//  JSON key of JWT expires at date.
//
static const char k_json_key_expires_at_chars[] = "exp";

//
//  JSON key of JWT expires at date.
//
static const vsc_str_t k_json_key_expires_at = {
    k_json_key_expires_at_chars,
    sizeof(k_json_key_expires_at_chars) - 1
};

//
//  Return size of 'vssc_jwt_payload_t'.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_ctx_size(void) {

    return sizeof(vssc_jwt_payload_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_jwt_payload_init(vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_payload_t));

    self->refcnt = 1;

    vssc_jwt_payload_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_jwt_payload_cleanup(vssc_jwt_payload_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_jwt_payload_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_jwt_payload_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_new(void) {

    vssc_jwt_payload_t *self = (vssc_jwt_payload_t *) vssc_alloc(sizeof (vssc_jwt_payload_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_payload_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined JWT Payload.
//
VSSC_PUBLIC void
vssc_jwt_payload_init_with_members(vssc_jwt_payload_t *self, vsc_str_t app_id, vsc_str_t identity, size_t issued_at,
        size_t expires_at) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_payload_t));

    self->refcnt = 1;

    vssc_jwt_payload_init_ctx_with_members(self, app_id, identity, issued_at, expires_at);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined JWT Payload.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_new_with_members(vsc_str_t app_id, vsc_str_t identity, size_t issued_at, size_t expires_at) {

    vssc_jwt_payload_t *self = (vssc_jwt_payload_t *) vssc_alloc(sizeof (vssc_jwt_payload_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_payload_init_with_members(self, app_id, identity, issued_at, expires_at);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_payload_init_with_json_object(vssc_jwt_payload_t *self, vssc_json_object_t **json_obj_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_payload_t));

    self->refcnt = 1;

    vssc_jwt_payload_init_ctx_with_json_object(self, json_obj_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static vssc_jwt_payload_t *
vssc_jwt_payload_new_with_json_object(vssc_json_object_t **json_obj_ref) {

    vssc_jwt_payload_t *self = (vssc_jwt_payload_t *) vssc_alloc(sizeof (vssc_jwt_payload_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_payload_init_with_json_object(self, json_obj_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_jwt_payload_delete(const vssc_jwt_payload_t *self) {

    vssc_jwt_payload_t *local_self = (vssc_jwt_payload_t *)self;

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

    vssc_jwt_payload_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_jwt_payload_new ()'.
//
VSSC_PUBLIC void
vssc_jwt_payload_destroy(vssc_jwt_payload_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_jwt_payload_t *self = *self_ref;
    *self_ref = NULL;

    vssc_jwt_payload_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_shallow_copy(vssc_jwt_payload_t *self) {

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
VSSC_PUBLIC const vssc_jwt_payload_t *
vssc_jwt_payload_shallow_copy_const(const vssc_jwt_payload_t *self) {

    return vssc_jwt_payload_shallow_copy((vssc_jwt_payload_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_payload_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_payload_init_ctx(vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_payload_cleanup_ctx(vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_object_destroy(&self->json_obj);
}

//
//  Create fully defined JWT Payload.
//
static void
vssc_jwt_payload_init_ctx_with_members(
        vssc_jwt_payload_t *self, vsc_str_t app_id, vsc_str_t identity, size_t issued_at, size_t expires_at) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(app_id));
    VSSC_ASSERT(vsc_str_is_valid(identity));
    VSSC_ASSERT(0 < issued_at && issued_at < INT_MAX);
    VSSC_ASSERT(0 < expires_at && expires_at < INT_MAX);
    VSSC_ASSERT(issued_at <= expires_at);

    const size_t app_id_str_len = k_json_value_prefix_app_id.len + app_id.len;
    const size_t identity_str_len = k_json_value_prefix_identity.len + identity.len;

    self->json_obj = vssc_json_object_new();

    vsc_str_buffer_t *tmp_str = vsc_str_buffer_new_with_capacity(VSSC_MAX(app_id_str_len, identity_str_len));

    vsc_str_buffer_reset(tmp_str);
    vsc_str_buffer_write_str(tmp_str, k_json_value_prefix_app_id);
    vsc_str_buffer_write_str(tmp_str, app_id);
    vsc_str_t prefixed_app_id = vsc_str_buffer_str(tmp_str);
    vssc_json_object_add_string_value(self->json_obj, k_json_key_app_id, prefixed_app_id);

    vsc_str_buffer_reset(tmp_str);
    vsc_str_buffer_write_str(tmp_str, k_json_value_prefix_identity);
    vsc_str_buffer_write_str(tmp_str, identity);
    vsc_str_t prefixed_identity = vsc_str_buffer_str(tmp_str);
    vssc_json_object_add_string_value(self->json_obj, k_json_key_identity, prefixed_identity);

    vsc_str_buffer_destroy(&tmp_str);

    vssc_json_object_add_int_value(self->json_obj, k_json_key_issued_at, (int)issued_at);
    vssc_json_object_add_int_value(self->json_obj, k_json_key_expires_at, (int)expires_at);
}

//
//  Create JWT Payload defined with a JSON object.
//  Prerequisite: The JSON object SHOULD be already validated.
//
static void
vssc_jwt_payload_init_ctx_with_json_object(vssc_jwt_payload_t *self, vssc_json_object_t **json_obj_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(json_obj_ref);

    self->json_obj = *json_obj_ref;
    *json_obj_ref = NULL;
}

//
//  Parse JWT Payload from a string representation.
//
VSSC_PUBLIC vssc_jwt_payload_t *
vssc_jwt_payload_parse(vsc_str_t payload_str, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid(payload_str));

    //
    //  Declare vars.
    //
    vssc_error_t inner_error;
    vssc_error_reset(&inner_error);

    const size_t payload_json_str_len = vssc_base64_url_decoded_len(payload_str.len);
    vsc_buffer_t *payload_json_buff = vsc_buffer_new_with_capacity(payload_json_str_len);

    vssc_json_object_t *json_obj = NULL;

    inner_error.status = vssc_base64_url_decode(payload_str, payload_json_buff);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    json_obj = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(payload_json_buff)), &inner_error);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    //
    //  Check fields.
    //
    vsc_str_t app_id = vssc_json_object_get_string_value(json_obj, k_json_key_app_id, &inner_error);
    if (vssc_error_has_error(&inner_error) || vsc_str_is_empty(app_id)) {
        goto fail;
    }


    vsc_str_t identity = vssc_json_object_get_string_value(json_obj, k_json_key_identity, &inner_error);
    if (vssc_error_has_error(&inner_error) || vsc_str_is_empty(identity)) {
        goto fail;
    }


    const int issued_at = vssc_json_object_get_int_value(json_obj, k_json_key_issued_at, &inner_error);
    if (vssc_error_has_error(&inner_error) || issued_at <= 0) {
        goto fail;
    }


    const int expires_at = vssc_json_object_get_int_value(json_obj, k_json_key_expires_at, &inner_error);
    if (vssc_error_has_error(&inner_error) || expires_at <= 0) {
        goto fail;
    }

    goto succ;

fail:

    vssc_json_object_destroy(&json_obj);

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);

succ:
    vsc_buffer_destroy(&payload_json_buff);

    if (json_obj) {
        return vssc_jwt_payload_new_with_json_object(&json_obj);
    } else {
        return NULL;
    }
}

//
//  Return lengh for buffer that can hold JWT Payload string representation.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_as_string_len(const vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_t json_str = vssc_jwt_payload_as_json_string(self);

    return vssc_base64_url_encoded_len(json_str.len);
}

//
//  Return JWT Payload string representation.
//  Representations is base64url.encode(json).
//
VSSC_PUBLIC void
vssc_jwt_payload_as_string(const vssc_jwt_payload_t *self, vsc_str_buffer_t *str_buffer) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_buffer_is_valid(str_buffer));
    VSSC_ASSERT(vsc_str_buffer_unused_len(str_buffer) >= vssc_jwt_payload_as_string_len(self));

    vsc_str_t json_str = vssc_jwt_payload_as_json_string(self);

    vssc_base64_url_encode(vsc_str_as_data(json_str), str_buffer);
}

//
//  Return JWT Payload as JSON string.
//
VSSC_PRIVATE vsc_str_t
vssc_jwt_payload_as_json_string(const vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    return vssc_json_object_as_str(self->json_obj);
}

//
//  Issuer application id.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_payload_app_id(const vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    vssc_error_t error;
    vssc_error_reset(&error);

    vsc_str_t prefixed_app_id = vssc_json_object_get_string_value(self->json_obj, k_json_key_app_id, &error);
    VSSC_ASSERT(!vssc_error_has_error(&error));
    VSSC_ASSERT(!vsc_str_is_empty(prefixed_app_id));

    return vsc_str_trim_prefix(prefixed_app_id, k_json_value_prefix_app_id);
}

//
//  Return identity to whom this token was issued.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_payload_identity(const vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    vssc_error_t error;
    vssc_error_reset(&error);

    vsc_str_t prefixed_identity = vssc_json_object_get_string_value(self->json_obj, k_json_key_identity, &error);
    VSSC_ASSERT(!vssc_error_has_error(&error));
    VSSC_ASSERT(!vsc_str_is_empty(prefixed_identity));

    return vsc_str_trim_prefix(prefixed_identity, k_json_value_prefix_identity);
}

//
//  Return UNIX Timestamp in seconds with issued date.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_issued_at(vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    vssc_error_t error;
    vssc_error_reset(&error);

    const int issued_at = vssc_json_object_get_int_value(self->json_obj, k_json_key_issued_at, &error);
    VSSC_ASSERT(!vssc_error_has_error(&error));
    VSSC_ASSERT(0 < issued_at);

    return (size_t)issued_at;
}

//
//  Return UNIX Timestamp in seconds with expiration date.
//
VSSC_PUBLIC size_t
vssc_jwt_payload_expires_at(vssc_jwt_payload_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->json_obj);

    vssc_error_t error;
    vssc_error_reset(&error);

    const int expires_at = vssc_json_object_get_int_value(self->json_obj, k_json_key_expires_at, &error);
    VSSC_ASSERT(!vssc_error_has_error(&error));
    VSSC_ASSERT(0 < expires_at);

    return (size_t)expires_at;
}
