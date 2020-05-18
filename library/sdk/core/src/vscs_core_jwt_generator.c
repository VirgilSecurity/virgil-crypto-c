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

#include "vscs_core_jwt_generator.h"
#include "vscs_core_memory.h"
#include "vscs_core_assert.h"
#include "vscs_core_jwt_generator_defs.h"
#include "vscs_core_base64_url.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <time.h>
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
//  Note, this method is called automatically when method vscs_core_jwt_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vscs_core_jwt_generator_init_ctx(vscs_core_jwt_generator_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscs_core_jwt_generator_cleanup_ctx(vscs_core_jwt_generator_t *self);

//
//  Create JWT generator with an application credentials.
//
static void
vscs_core_jwt_generator_init_ctx_with_credentials(vscs_core_jwt_generator_t *self, vsc_str_t app_id,
        vsc_str_t app_key_id, const vscf_impl_t *app_key);

//
//  This method is called when interface 'random' was setup.
//
static void
vscs_core_jwt_generator_did_setup_random(vscs_core_jwt_generator_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscs_core_jwt_generator_did_release_random(vscs_core_jwt_generator_t *self);

//
//  Return size of 'vscs_core_jwt_generator_t'.
//
VSCS_CORE_PUBLIC size_t
vscs_core_jwt_generator_ctx_size(void) {

    return sizeof(vscs_core_jwt_generator_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_init(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    vscs_core_zeroize(self, sizeof(vscs_core_jwt_generator_t));

    self->refcnt = 1;

    vscs_core_jwt_generator_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_cleanup(vscs_core_jwt_generator_t *self) {

    if (self == NULL) {
        return;
    }

    vscs_core_jwt_generator_cleanup_ctx(self);

    vscs_core_jwt_generator_release_random(self);

    vscs_core_zeroize(self, sizeof(vscs_core_jwt_generator_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_new(void) {

    vscs_core_jwt_generator_t *self = (vscs_core_jwt_generator_t *) vscs_core_alloc(sizeof (vscs_core_jwt_generator_t));
    VSCS_CORE_ASSERT_ALLOC(self);

    vscs_core_jwt_generator_init(self);

    self->self_dealloc_cb = vscs_core_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create JWT generator with an application credentials.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_init_with_credentials(vscs_core_jwt_generator_t *self, vsc_str_t app_id, vsc_str_t app_key_id,
        const vscf_impl_t *app_key) {

    VSCS_CORE_ASSERT_PTR(self);

    vscs_core_zeroize(self, sizeof(vscs_core_jwt_generator_t));

    self->refcnt = 1;

    vscs_core_jwt_generator_init_ctx_with_credentials(self, app_id, app_key_id, app_key);
}

//
//  Allocate class context and perform it's initialization.
//  Create JWT generator with an application credentials.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_new_with_credentials(vsc_str_t app_id, vsc_str_t app_key_id, const vscf_impl_t *app_key) {

    vscs_core_jwt_generator_t *self = (vscs_core_jwt_generator_t *) vscs_core_alloc(sizeof (vscs_core_jwt_generator_t));
    VSCS_CORE_ASSERT_ALLOC(self);

    vscs_core_jwt_generator_init_with_credentials(self, app_id, app_key_id, app_key);

    self->self_dealloc_cb = vscs_core_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_delete(vscs_core_jwt_generator_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCS_CORE_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCS_CORE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCS_CORE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCS_CORE_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscs_core_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscs_core_jwt_generator_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscs_core_jwt_generator_new ()'.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_destroy(vscs_core_jwt_generator_t **self_ref) {

    VSCS_CORE_ASSERT_PTR(self_ref);

    vscs_core_jwt_generator_t *self = *self_ref;
    *self_ref = NULL;

    vscs_core_jwt_generator_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCS_CORE_PUBLIC vscs_core_jwt_generator_t *
vscs_core_jwt_generator_shallow_copy(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    #if defined(VSCS_CORE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCS_CORE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_use_random(vscs_core_jwt_generator_t *self, vscf_impl_t *random) {

    VSCS_CORE_ASSERT_PTR(self);
    VSCS_CORE_ASSERT_PTR(random);
    VSCS_CORE_ASSERT(self->random == NULL);

    VSCS_CORE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vscs_core_jwt_generator_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_take_random(vscs_core_jwt_generator_t *self, vscf_impl_t *random) {

    VSCS_CORE_ASSERT_PTR(self);
    VSCS_CORE_ASSERT_PTR(random);
    VSCS_CORE_ASSERT(self->random == NULL);

    VSCS_CORE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vscs_core_jwt_generator_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_release_random(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vscs_core_jwt_generator_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscs_core_jwt_generator_init() is called.
//  Note, that context is already zeroed.
//
static void
vscs_core_jwt_generator_init_ctx(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscs_core_jwt_generator_cleanup_ctx(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    vsc_str_buffer_destroy(&self->app_id);
    vsc_str_buffer_destroy(&self->app_key_id);
    vscf_impl_destroy((vscf_impl_t **)&self->app_key);
    vscf_signer_destroy(&self->signer);
}

//
//  Create JWT generator with an application credentials.
//
static void
vscs_core_jwt_generator_init_ctx_with_credentials(
        vscs_core_jwt_generator_t *self, vsc_str_t app_id, vsc_str_t app_key_id, const vscf_impl_t *app_key) {

    VSCS_CORE_ASSERT_PTR(self);
    VSCS_CORE_ASSERT_PTR(app_key);

    self->app_id = vsc_str_buffer_new_with_str(app_id);
    self->app_key_id = vsc_str_buffer_new_with_str(app_key_id);
    self->app_key = vscf_impl_shallow_copy_const(app_key);
    self->ttl = vscs_core_jwt_generator_DEFAULT_TTL;
    self->signer = vscf_signer_new();
    vscf_signer_take_hash(self->signer, vscf_sha512_impl(vscf_sha512_new()));
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscs_core_jwt_generator_did_setup_random(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    vscf_signer_release_random(self->signer);
    vscf_signer_use_random(self->signer, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vscs_core_jwt_generator_did_release_random(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    if (self->signer) {
        vscf_signer_release_random(self->signer);
    }
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCS_CORE_PUBLIC vscs_core_status_t
vscs_core_jwt_generator_setup_defaults(vscs_core_jwt_generator_t *self) {

    VSCS_CORE_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return vscs_core_status_INIT_RANDOM_FAILED;
        }

        vscs_core_jwt_generator_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vscs_core_status_SUCCESS;
}

//
//  Set JWT TTL.
//
VSCS_CORE_PUBLIC void
vscs_core_jwt_generator_set_ttl(vscs_core_jwt_generator_t *self, size_t ttl) {

    VSCS_CORE_ASSERT_PTR(self);

    self->ttl = ttl;
}

//
//  Generate new JWT.
//
VSCS_CORE_PUBLIC vscs_core_jwt_t *
vscs_core_jwt_generator_generate_token(
        const vscs_core_jwt_generator_t *self, vsc_str_t identity, vscs_core_error_t *error) {

    VSCS_CORE_ASSERT_PTR(self);
    VSCS_CORE_ASSERT_PTR(self->signer);

    const size_t issued_at = (size_t)time(NULL);
    const size_t expires_at = issued_at + self->ttl;

    vscs_core_jwt_header_t *jwt_header = vscs_core_jwt_header_new_with_app_key_id(vsc_str_buffer_str(self->app_key_id));

    vscs_core_jwt_payload_t *jwt_payload =
            vscs_core_jwt_payload_new_with_members(vsc_str_buffer_str(self->app_id), identity, issued_at, expires_at);


    const size_t jwt_header_encoded_len = vscs_core_jwt_header_as_string_len(jwt_header);
    const size_t jwt_payload_encoded_len = vscs_core_jwt_payload_as_string_len(jwt_payload);
    const size_t jwt_signature_len = vscf_signer_signature_len(self->signer, self->app_key);
    const size_t jwt_signature_encoded_len = vscs_core_base64_url_encoded_len(jwt_signature_len);
    const size_t jwt_string_len = jwt_header_encoded_len + jwt_payload_encoded_len + jwt_signature_encoded_len + 2;

    vsc_buffer_t *jwt_signature = vsc_buffer_new_with_capacity(jwt_signature_len);
    vsc_str_buffer_t *jwt_string = vsc_str_buffer_new_with_capacity(jwt_string_len);

    vscs_core_jwt_header_as_string(jwt_header, jwt_string);

    vsc_str_buffer_write_char(jwt_string, '.');

    vscs_core_jwt_payload_as_string(jwt_payload, jwt_string);

    vsc_str_buffer_write_char(jwt_string, '.');

    vscf_signer_reset(self->signer);
    vscf_signer_append_data(self->signer, vsc_str_buffer_data(jwt_string));

    const vscf_status_t signer_status = vscf_signer_sign(self->signer, self->app_key, jwt_signature);

    if (signer_status == vscf_status_SUCCESS) {
        vscs_core_base64_url_encode(vsc_buffer_data(jwt_signature), jwt_string);

        return vscs_core_jwt_new_with_members_disown(&jwt_header, &jwt_payload, &jwt_signature, &jwt_string);
    }

    vscs_core_jwt_header_destroy(&jwt_header);
    vscs_core_jwt_payload_destroy(&jwt_payload);
    vsc_buffer_destroy(&jwt_signature);
    vsc_str_buffer_destroy(&jwt_string);

    VSCS_CORE_ERROR_SAFE_UPDATE(error, vscs_core_status_SIGN_JWT_FAILED);

    return NULL;
}
