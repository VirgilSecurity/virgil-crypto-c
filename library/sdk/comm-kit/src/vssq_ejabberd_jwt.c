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
//  Class that handles Ejabberd JWT.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_ejabberd_jwt.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_ejabberd_jwt_defs.h"

#include <virgil/sdk/core/vssc_unix_time.h>
#include <virgil/sdk/core/vssc_base64_url.h>
#include <virgil/sdk/core/vssc_json_object.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_ejabberd_jwt_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_ejabberd_jwt_init_ctx(vssq_ejabberd_jwt_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_ejabberd_jwt_cleanup_ctx(vssq_ejabberd_jwt_t *self);

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
static void
vssq_ejabberd_jwt_init_with_members(vssq_ejabberd_jwt_t *self, vsc_str_t jwt_string, vsc_str_t jid, size_t expires_at);

//
//  Create fully defined object.
//
static void
vssq_ejabberd_jwt_init_ctx_with_members(vssq_ejabberd_jwt_t *self, vsc_str_t jwt_string, vsc_str_t jid,
        size_t expires_at);

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
static vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_new_with_members(vsc_str_t jwt_string, vsc_str_t jid, size_t expires_at);

//
//  JSON key of JWT Ejabberd JID.
//
static const char k_json_key_jid_chars[] = "jid";

//
//  JSON key of JWT Ejabberd JID.
//
static const vsc_str_t k_json_key_jid = {
    k_json_key_jid_chars,
    sizeof(k_json_key_jid_chars) - 1
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
//  Return size of 'vssq_ejabberd_jwt_t'.
//
VSSQ_PUBLIC size_t
vssq_ejabberd_jwt_ctx_size(void) {

    return sizeof(vssq_ejabberd_jwt_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_init(vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_ejabberd_jwt_t));

    self->refcnt = 1;

    vssq_ejabberd_jwt_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_cleanup(vssq_ejabberd_jwt_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_ejabberd_jwt_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_ejabberd_jwt_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_new(void) {

    vssq_ejabberd_jwt_t *self = (vssq_ejabberd_jwt_t *) vssq_alloc(sizeof (vssq_ejabberd_jwt_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_ejabberd_jwt_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined object.
//
static void
vssq_ejabberd_jwt_init_with_members(vssq_ejabberd_jwt_t *self, vsc_str_t jwt_string, vsc_str_t jid, size_t expires_at) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_ejabberd_jwt_t));

    self->refcnt = 1;

    vssq_ejabberd_jwt_init_ctx_with_members(self, jwt_string, jid, expires_at);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined object.
//
static vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_new_with_members(vsc_str_t jwt_string, vsc_str_t jid, size_t expires_at) {

    vssq_ejabberd_jwt_t *self = (vssq_ejabberd_jwt_t *) vssq_alloc(sizeof (vssq_ejabberd_jwt_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_ejabberd_jwt_init_with_members(self, jwt_string, jid, expires_at);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_delete(const vssq_ejabberd_jwt_t *self) {

    vssq_ejabberd_jwt_t *local_self = (vssq_ejabberd_jwt_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSQ_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSQ_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssq_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssq_ejabberd_jwt_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_ejabberd_jwt_new ()'.
//
VSSQ_PUBLIC void
vssq_ejabberd_jwt_destroy(vssq_ejabberd_jwt_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_ejabberd_jwt_t *self = *self_ref;
    *self_ref = NULL;

    vssq_ejabberd_jwt_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_shallow_copy(vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_shallow_copy_const(const vssq_ejabberd_jwt_t *self) {

    return vssq_ejabberd_jwt_shallow_copy((vssq_ejabberd_jwt_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_ejabberd_jwt_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_ejabberd_jwt_init_ctx(vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_ejabberd_jwt_cleanup_ctx(vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->jwt_string);
    vsc_str_mutable_release(&self->jid);
}

//
//  Create fully defined object.
//
static void
vssq_ejabberd_jwt_init_ctx_with_members(
        vssq_ejabberd_jwt_t *self, vsc_str_t jwt_string, vsc_str_t jid, size_t expires_at) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid(jwt_string));
    VSSQ_ASSERT(!vsc_str_is_empty(jwt_string));
    VSSQ_ASSERT(vsc_str_is_valid(jid));
    VSSQ_ASSERT(!vsc_str_is_empty(jid));
    VSSQ_ASSERT(expires_at > 0);

    self->jwt_string = vsc_str_mutable_from_str(jwt_string);
    self->jid = vsc_str_mutable_from_str(jid);
    self->expires_at = expires_at;
}

//
//  Parse Ejabberd JWT from a string representation.
//
VSSQ_PUBLIC vssq_ejabberd_jwt_t *
vssq_ejabberd_jwt_parse(vsc_str_t str, vssq_error_t *error) {

    VSSQ_ASSERT(vsc_str_is_valid(str));

    if (vsc_str_is_empty(str)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_PARSE_EJABBERD_JWT_FAILED);
        return NULL;
    }

    vsc_str_t header_str = vsc_str_empty();
    vsc_str_t payload_str = vsc_str_empty();
    vsc_str_t signature_str = vsc_str_empty();

    const char *curr = str.chars;
    const char *end = str.chars + str.len;

    //
    //  Extract JWT Header as string.
    //
    for (size_t len = 0; curr + len < end; ++len) {
        if (curr[len] == '.') {
            header_str = vsc_str(curr, len);
            curr += len + 1;
            break;
        }
    }

    if (vsc_str_is_empty(header_str)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_PARSE_EJABBERD_JWT_FAILED);
        return NULL;
    }

    //
    //  Extract JWT Payload as string.
    //
    for (size_t len = 0; curr + len < end; ++len) {
        if (curr[len] == '.') {
            payload_str = vsc_str(curr, len);
            curr += len + 1;
            break;
        }
    }

    if (vsc_str_is_empty(payload_str)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_PARSE_EJABBERD_JWT_FAILED);
        return NULL;
    }

    //
    //  Extract JWT Signature as string.
    //
    if (curr < end) {
        signature_str = vsc_str(curr, (size_t)(end - curr));
    }

    if (vsc_str_is_empty(signature_str)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_PARSE_EJABBERD_JWT_FAILED);
        return NULL;
    }

    //
    //  Parse Payload.
    //
    vssc_error_t inner_error;
    vssc_error_reset(&inner_error);

    const size_t payload_json_str_len = vssc_base64_url_decoded_len(payload_str.len);
    vsc_buffer_t *payload_json_buff = vsc_buffer_new_with_capacity(payload_json_str_len);

    vssc_json_object_t *payload_json_obj = NULL;
    vssq_ejabberd_jwt_t *ejabberd_jwt = NULL;

    vsc_str_t jid = vsc_str_empty();
    int expires_at = 0;

    inner_error.status = vssc_base64_url_decode(payload_str, payload_json_buff);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    payload_json_obj = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(payload_json_buff)), &inner_error);
    if (vssc_error_has_error(&inner_error)) {
        goto fail;
    }

    //
    //  Check fields.
    //
    jid = vssc_json_object_get_string_value(payload_json_obj, k_json_key_jid, &inner_error);
    if (vssc_error_has_error(&inner_error) || vsc_str_is_empty(jid)) {
        goto fail;
    }

    expires_at = vssc_json_object_get_int_value(payload_json_obj, k_json_key_expires_at, &inner_error);
    if (vssc_error_has_error(&inner_error) || expires_at <= 0) {
        goto fail;
    }

    ejabberd_jwt = vssq_ejabberd_jwt_new_with_members(str, jid, (size_t)expires_at);

    goto cleanup;

fail:
    VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_PARSE_EJABBERD_JWT_FAILED);

cleanup:
    vssc_json_object_destroy(&payload_json_obj);
    vsc_buffer_destroy(&payload_json_buff);

    return ejabberd_jwt;
}

//
//  Return Ejabberd JWT string representation.
//
VSSQ_PUBLIC vsc_str_t
vssq_ejabberd_jwt_as_string(const vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vsc_str_mutable_is_valid(self->jwt_string));

    return vsc_str_mutable_as_str(self->jwt_string);
}

//
//  Return identity to whom this token was issued.
//
VSSQ_PUBLIC vsc_str_t
vssq_ejabberd_jwt_jid(const vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(vsc_str_mutable_is_valid(self->jid));

    return vsc_str_mutable_as_str(self->jid);
}

//
//  Return true if token is expired.
//
VSSQ_PUBLIC bool
vssq_ejabberd_jwt_is_expired(const vssq_ejabberd_jwt_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->expires_at != 0);

    return self->expires_at;
}
