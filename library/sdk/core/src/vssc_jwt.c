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
//  Class that handles JWT.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_jwt.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_jwt_private.h"
#include "vssc_jwt_defs.h"
#include "vssc_unix_time.h"
#include "vssc_base64_url.h"
#include "vssc_jwt_header.h"
#include "vssc_jwt_payload.h"

#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_str_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_init_ctx(vssc_jwt_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_cleanup_ctx(vssc_jwt_t *self);

//
//  Create object with all members defined.
//
static void
vssc_jwt_init_ctx_with_members_disown(vssc_jwt_t *self, vssc_jwt_header_t **header_ref,
        vssc_jwt_payload_t **payload_ref, vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref);

//
//  Return size of 'vssc_jwt_t'.
//
VSSC_PUBLIC size_t
vssc_jwt_ctx_size(void) {

    return sizeof(vssc_jwt_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_jwt_init(vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_t));

    self->refcnt = 1;

    vssc_jwt_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_jwt_cleanup(vssc_jwt_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_jwt_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_jwt_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_new(void) {

    vssc_jwt_t *self = (vssc_jwt_t *) vssc_alloc(sizeof (vssc_jwt_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object with all members defined.
//
VSSC_PUBLIC void
vssc_jwt_init_with_members_disown(vssc_jwt_t *self, vssc_jwt_header_t **header_ref, vssc_jwt_payload_t **payload_ref,
        vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_t));

    self->refcnt = 1;

    vssc_jwt_init_ctx_with_members_disown(self, header_ref, payload_ref, signature_ref, jwt_string_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create object with all members defined.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_new_with_members_disown(vssc_jwt_header_t **header_ref, vssc_jwt_payload_t **payload_ref,
        vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref) {

    vssc_jwt_t *self = (vssc_jwt_t *) vssc_alloc(sizeof (vssc_jwt_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_init_with_members_disown(self, header_ref, payload_ref, signature_ref, jwt_string_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_jwt_delete(const vssc_jwt_t *self) {

    vssc_jwt_t *local_self = (vssc_jwt_t *)self;

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

    vssc_jwt_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_jwt_new ()'.
//
VSSC_PUBLIC void
vssc_jwt_destroy(vssc_jwt_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_jwt_t *self = *self_ref;
    *self_ref = NULL;

    vssc_jwt_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_shallow_copy(vssc_jwt_t *self) {

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
VSSC_PUBLIC const vssc_jwt_t *
vssc_jwt_shallow_copy_const(const vssc_jwt_t *self) {

    return vssc_jwt_shallow_copy((vssc_jwt_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_init_ctx(vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_cleanup_ctx(vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_jwt_header_destroy(&self->header);
    vssc_jwt_payload_destroy(&self->payload);
    vsc_buffer_destroy(&self->signature);
    vsc_str_buffer_destroy(&self->jwt_string);
}

//
//  Create object with all members defined.
//
static void
vssc_jwt_init_ctx_with_members_disown(vssc_jwt_t *self, vssc_jwt_header_t **header_ref,
        vssc_jwt_payload_t **payload_ref, vsc_buffer_t **signature_ref, vsc_str_buffer_t **jwt_string_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(header_ref);
    VSSC_ASSERT_REF(payload_ref);
    VSSC_ASSERT_REF(signature_ref);
    VSSC_ASSERT_REF(jwt_string_ref);

    self->header = *header_ref;
    self->payload = *payload_ref;
    self->signature = *signature_ref;
    self->jwt_string = *jwt_string_ref;

    *header_ref = NULL;
    *payload_ref = NULL;
    *signature_ref = NULL;
    *jwt_string_ref = NULL;
}

//
//  Parse JWT from a string representation.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_parse(vsc_str_t str, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid(str));

    if (vsc_str_is_empty(str)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);
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
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);
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
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);
        return NULL;
    }

    //
    //  Extract JWT Signature as string.
    //
    if (curr < end) {
        signature_str = vsc_str(curr, (size_t)(end - curr));
    }

    if (vsc_str_is_empty(signature_str)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);
        return NULL;
    }

    vssc_jwt_header_t *header = NULL;
    vssc_jwt_payload_t *payload = NULL;
    vsc_buffer_t *signature = NULL;
    vsc_str_buffer_t *str_buf = NULL;

    //
    //  Parse JWT Header.
    //
    header = vssc_jwt_header_parse(header_str, NULL);
    if (NULL == header) {
        goto error;
    }

    //
    //  Parse JWT Payload.
    //
    payload = vssc_jwt_payload_parse(payload_str, NULL);
    if (NULL == payload) {
        goto error;
    }

    //
    //  Parse JWT Signature.
    //
    const size_t signature_buf_len = vssc_base64_url_decoded_len(signature_str.len);
    signature = vsc_buffer_new_with_capacity(signature_buf_len);

    const vssc_status_t signature_parse_status = vssc_base64_url_decode(signature_str, signature);
    if (signature_parse_status != vssc_status_SUCCESS) {
        goto error;
    }

    str_buf = vsc_str_buffer_new_with_str(str);

    return vssc_jwt_new_with_members_disown(&header, &payload, &signature, &str_buf);


error:
    vssc_jwt_header_destroy(&header);
    vssc_jwt_payload_destroy(&payload);
    vsc_buffer_destroy(&signature);

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PARSE_JWT_FAILED);

    return NULL;
}

//
//  Return JWT string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_as_string(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->jwt_string);

    return vsc_str_buffer_str(self->jwt_string);
}

//
//  Return identity to whom this token was issued.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_identity(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->payload);

    return vssc_jwt_payload_identity(self->payload);
}

//
//  Return true if token is expired.
//
VSSC_PUBLIC bool
vssc_jwt_is_expired(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->payload);

    size_t now = vssc_unix_time_now();
    size_t expires_at = vssc_jwt_payload_expires_at(self->payload);

    return now >= expires_at;
}

//
//  Return JWT Header string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_header_string(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->jwt_string);

    const char *begin = vsc_str_buffer_begin(self->jwt_string);
    const size_t len = vsc_str_buffer_len(self->jwt_string);

    const char *first_dot = vssc_strnstr(begin, ".", len);
    VSSC_ASSERT(first_dot);
    VSSC_ASSERT(begin < first_dot);

    vsc_str_t result = vsc_str(begin, (size_t)(first_dot - begin));

    return result;
}

//
//  Return JWT Payload string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_payload_string(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->jwt_string);

    const char *begin = vsc_str_buffer_begin(self->jwt_string);
    const char *end = begin + vsc_str_buffer_len(self->jwt_string);

    const char *first_dot = vssc_strnstr(begin, ".", (size_t)(end - begin));
    VSSC_ASSERT(first_dot);
    VSSC_ASSERT(begin < first_dot);

    const char *payload_begin = first_dot + 1;

    const char *second_dot = vssc_strnstr(payload_begin, ".", (size_t)(end - payload_begin));
    VSSC_ASSERT(second_dot);
    VSSC_ASSERT(payload_begin < second_dot);

    vsc_str_t result = vsc_str(payload_begin, (size_t)(second_dot - payload_begin));

    return result;
}

//
//  Return JWT Signature string representation.
//
VSSC_PUBLIC vsc_str_t
vssc_jwt_get_signature_string(const vssc_jwt_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_empty();
}
