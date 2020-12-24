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
//  Class responsible for JWT generation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_jwt_generator.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_jwt_generator_defs.h"
#include "vssc_unix_time.h"
#include "vssc_base64_url.h"
#include "vssc_jwt_private.h"

#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_generator_init_ctx(vssc_jwt_generator_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_generator_cleanup_ctx(vssc_jwt_generator_t *self);

//
//  Create JWT generator with an application credentials.
//
static void
vssc_jwt_generator_init_ctx_with_credentials(vssc_jwt_generator_t *self, vsc_str_t app_id, vsc_str_t app_key_id,
        const vscf_impl_t *app_key);

//
//  This method is called when interface 'random' was setup.
//
static void
vssc_jwt_generator_did_setup_random(vssc_jwt_generator_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssc_jwt_generator_did_release_random(vssc_jwt_generator_t *self);

//
//  Return size of 'vssc_jwt_generator_t'.
//
VSSC_PUBLIC size_t
vssc_jwt_generator_ctx_size(void) {

    return sizeof(vssc_jwt_generator_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_jwt_generator_init(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_generator_t));

    self->refcnt = 1;

    vssc_jwt_generator_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_jwt_generator_cleanup(vssc_jwt_generator_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_jwt_generator_release_random(self);

    vssc_jwt_generator_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_jwt_generator_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_jwt_generator_t *
vssc_jwt_generator_new(void) {

    vssc_jwt_generator_t *self = (vssc_jwt_generator_t *) vssc_alloc(sizeof (vssc_jwt_generator_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_generator_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create JWT generator with an application credentials.
//
VSSC_PUBLIC void
vssc_jwt_generator_init_with_credentials(vssc_jwt_generator_t *self, vsc_str_t app_id, vsc_str_t app_key_id,
        const vscf_impl_t *app_key) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_jwt_generator_t));

    self->refcnt = 1;

    vssc_jwt_generator_init_ctx_with_credentials(self, app_id, app_key_id, app_key);
}

//
//  Allocate class context and perform it's initialization.
//  Create JWT generator with an application credentials.
//
VSSC_PUBLIC vssc_jwt_generator_t *
vssc_jwt_generator_new_with_credentials(vsc_str_t app_id, vsc_str_t app_key_id, const vscf_impl_t *app_key) {

    vssc_jwt_generator_t *self = (vssc_jwt_generator_t *) vssc_alloc(sizeof (vssc_jwt_generator_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_jwt_generator_init_with_credentials(self, app_id, app_key_id, app_key);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_jwt_generator_delete(const vssc_jwt_generator_t *self) {

    vssc_jwt_generator_t *local_self = (vssc_jwt_generator_t *)self;

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

    vssc_jwt_generator_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_jwt_generator_new ()'.
//
VSSC_PUBLIC void
vssc_jwt_generator_destroy(vssc_jwt_generator_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_jwt_generator_t *self = *self_ref;
    *self_ref = NULL;

    vssc_jwt_generator_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_jwt_generator_t *
vssc_jwt_generator_shallow_copy(vssc_jwt_generator_t *self) {

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
VSSC_PUBLIC const vssc_jwt_generator_t *
vssc_jwt_generator_shallow_copy_const(const vssc_jwt_generator_t *self) {

    return vssc_jwt_generator_shallow_copy((vssc_jwt_generator_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSC_PUBLIC void
vssc_jwt_generator_use_random(vssc_jwt_generator_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssc_jwt_generator_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSC_PUBLIC void
vssc_jwt_generator_take_random(vssc_jwt_generator_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssc_jwt_generator_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSC_PUBLIC void
vssc_jwt_generator_release_random(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssc_jwt_generator_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_jwt_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_jwt_generator_init_ctx(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_jwt_generator_cleanup_ctx(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_destroy(&self->app_id);
    vsc_str_buffer_destroy(&self->app_key_id);
    vscf_impl_destroy((vscf_impl_t **)&self->app_key);
    vscf_signer_destroy(&self->signer);
}

//
//  Create JWT generator with an application credentials.
//
static void
vssc_jwt_generator_init_ctx_with_credentials(
        vssc_jwt_generator_t *self, vsc_str_t app_id, vsc_str_t app_key_id, const vscf_impl_t *app_key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(app_key);

    self->app_id = vsc_str_buffer_new_with_str(app_id);
    self->app_key_id = vsc_str_buffer_new_with_str(app_key_id);
    self->app_key = vscf_impl_shallow_copy_const(app_key);
    self->ttl = vssc_jwt_generator_DEFAULT_TTL;
    self->signer = vscf_signer_new();
    vscf_signer_take_hash(self->signer, vscf_sha512_impl(vscf_sha512_new()));
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssc_jwt_generator_did_setup_random(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    vscf_signer_release_random(self->signer);
    vscf_signer_use_random(self->signer, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssc_jwt_generator_did_release_random(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    if (self->signer) {
        vscf_signer_release_random(self->signer);
    }
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSC_PUBLIC vssc_status_t
vssc_jwt_generator_setup_defaults(vssc_jwt_generator_t *self) {

    VSSC_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return vssc_status_INIT_RANDOM_FAILED;
        }

        vssc_jwt_generator_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vssc_status_SUCCESS;
}

//
//  Set JWT TTL.
//
VSSC_PUBLIC void
vssc_jwt_generator_set_ttl(vssc_jwt_generator_t *self, size_t ttl) {

    VSSC_ASSERT_PTR(self);

    self->ttl = ttl;
}

//
//  Generate new JWT.
//
VSSC_PUBLIC vssc_jwt_t *
vssc_jwt_generator_generate_token(const vssc_jwt_generator_t *self, vsc_str_t identity, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->signer);

    const size_t issued_at = vssc_unix_time_now();
    const size_t expires_at = issued_at + self->ttl;

    vssc_jwt_header_t *jwt_header = vssc_jwt_header_new_with_app_key_id(vsc_str_buffer_str(self->app_key_id));

    vssc_jwt_payload_t *jwt_payload =
            vssc_jwt_payload_new_with_members(vsc_str_buffer_str(self->app_id), identity, issued_at, expires_at);


    const size_t jwt_header_encoded_len = vssc_jwt_header_as_string_len(jwt_header);
    const size_t jwt_payload_encoded_len = vssc_jwt_payload_as_string_len(jwt_payload);
    const size_t jwt_signature_len = vscf_signer_signature_len(self->signer, self->app_key);
    const size_t jwt_signature_encoded_len = vssc_base64_url_encoded_len(jwt_signature_len);
    const size_t jwt_string_len = jwt_header_encoded_len + jwt_payload_encoded_len + jwt_signature_encoded_len + 2;

    vsc_buffer_t *jwt_signature = vsc_buffer_new_with_capacity(jwt_signature_len);
    vsc_str_buffer_t *jwt_string = vsc_str_buffer_new_with_capacity(jwt_string_len);

    vssc_jwt_header_as_string(jwt_header, jwt_string);

    vsc_str_buffer_write_char(jwt_string, '.');

    vssc_jwt_payload_as_string(jwt_payload, jwt_string);

    vscf_signer_reset(self->signer);
    vscf_signer_append_data(self->signer, vsc_str_buffer_data(jwt_string));

    const vscf_status_t signer_status = vscf_signer_sign(self->signer, self->app_key, jwt_signature);

    if (signer_status == vscf_status_SUCCESS) {
        vsc_str_buffer_write_char(jwt_string, '.');

        vssc_base64_url_encode(vsc_buffer_data(jwt_signature), jwt_string);

        return vssc_jwt_new_with_members_disown(&jwt_header, &jwt_payload, &jwt_signature, &jwt_string);
    }

    vssc_jwt_header_destroy(&jwt_header);
    vssc_jwt_payload_destroy(&jwt_payload);
    vsc_buffer_destroy(&jwt_signature);
    vsc_str_buffer_destroy(&jwt_string);

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_SIGN_JWT_FAILED);

    return NULL;
}
