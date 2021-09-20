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


//  @description
// --------------------------------------------------------------------------
//  Class responsible for operations with Virgil Cards and it's representations.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_card_manager.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_card_manager_defs.h"
#include "vssc_unix_time.h"
#include "vssc_raw_card_verifier.h"
#include "vssc_raw_card_signer.h"
#include "vssc_card_private.h"
#include "vssc_card_list_private.h"

#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_signer.h>
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
//  Note, this method is called automatically when method vssc_card_manager_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_manager_init_ctx(vssc_card_manager_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_manager_cleanup_ctx(vssc_card_manager_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vssc_card_manager_did_setup_random(vssc_card_manager_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssc_card_manager_did_release_random(vssc_card_manager_t *self);

//
//  Generates self-signed "raw card" with an optional previous card id.
//
static vssc_raw_card_t *
vssc_card_manager_generate_raw_card_inner(const vssc_card_manager_t *self, vsc_str_t identity,
        const vscf_impl_t *private_key, vsc_str_t previous_card_id, vssc_error_t *error);

//
//  Return size of 'vssc_card_manager_t'.
//
VSSC_PUBLIC size_t
vssc_card_manager_ctx_size(void) {

    return sizeof(vssc_card_manager_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_manager_init(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_manager_t));

    self->refcnt = 1;

    vssc_card_manager_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_manager_cleanup(vssc_card_manager_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_card_manager_release_random(self);

    vssc_card_manager_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_card_manager_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_manager_t *
vssc_card_manager_new(void) {

    vssc_card_manager_t *self = (vssc_card_manager_t *) vssc_alloc(sizeof (vssc_card_manager_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_manager_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_manager_delete(const vssc_card_manager_t *self) {

    vssc_card_manager_t *local_self = (vssc_card_manager_t *)self;

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

    vssc_card_manager_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_manager_new ()'.
//
VSSC_PUBLIC void
vssc_card_manager_destroy(vssc_card_manager_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_card_manager_t *self = *self_ref;
    *self_ref = NULL;

    vssc_card_manager_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_manager_t *
vssc_card_manager_shallow_copy(vssc_card_manager_t *self) {

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
VSSC_PUBLIC const vssc_card_manager_t *
vssc_card_manager_shallow_copy_const(const vssc_card_manager_t *self) {

    return vssc_card_manager_shallow_copy((vssc_card_manager_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSC_PUBLIC void
vssc_card_manager_use_random(vssc_card_manager_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssc_card_manager_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSC_PUBLIC void
vssc_card_manager_take_random(vssc_card_manager_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssc_card_manager_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSC_PUBLIC void
vssc_card_manager_release_random(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssc_card_manager_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_manager_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_manager_init_ctx(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    self->raw_card_signer = vssc_raw_card_signer_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_manager_cleanup_ctx(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_raw_card_signer_destroy(&self->raw_card_signer);
    vscf_impl_destroy(&self->virgil_public_key);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssc_card_manager_did_setup_random(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_raw_card_signer_use_random(self->raw_card_signer, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssc_card_manager_did_release_random(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_raw_card_signer_release_random(self->raw_card_signer);
}

//
//  Configure internal states and dependencies.
//
VSSC_PUBLIC vssc_status_t
vssc_card_manager_configure(vssc_card_manager_t *self) {

    VSSC_ASSERT_PTR(self);

    static const byte k_virgil_public_key[] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            0x96, 0x33, 0x98, 0x18, 0x03, 0x58, 0x89, 0x5a, 0xb5, 0x59, 0xbb, 0xd5, 0xbe, 0x86, 0x08, 0x2a, 0xdb, 0xd9,
            0x8b, 0x68, 0xe2, 0xf5, 0xb0, 0x21, 0xc7, 0x2b, 0xba, 0x89, 0x5f, 0xcb, 0x17, 0xc3};

    return vssc_card_manager_configure_with_service_public_key(
            self, vsc_data(k_virgil_public_key, sizeof(k_virgil_public_key)));
}

//
//  Configure internal states and dependencies.
//  Virgil Service Public Key can be customized (i.e. for stage env).
//
VSSC_PUBLIC vssc_status_t
vssc_card_manager_configure_with_service_public_key(vssc_card_manager_t *self, vsc_data_t public_key_data) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->random);

    //
    //  Setup dependencies.
    //
    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return vssc_status_INIT_RANDOM_FAILED;
        }
        vssc_card_manager_take_random(self, vscf_ctr_drbg_impl(random));
    }

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    self->virgil_public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &foundation_error);

    vscf_key_provider_destroy(&key_provider);

    if (vscf_error_has_error(&foundation_error)) {
        return vssc_status_IMPORT_PUBLIC_KEY_FAILED;
    }

    return vssc_status_SUCCESS;
}

//
//  Generates self-signed "raw card".
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_manager_generate_raw_card(
        const vssc_card_manager_t *self, vsc_str_t identity, const vscf_impl_t *private_key, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT_PTR(private_key);
    VSSC_ASSERT(vscf_private_key_is_implemented(private_key));

    return vssc_card_manager_generate_raw_card_inner(self, identity, private_key, vsc_str_empty(), error);
}

//
//  Generates self-signed "raw card" with a defined previous card id.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_card_manager_generate_replacement_raw_card(const vssc_card_manager_t *self, vsc_str_t identity,
        const vscf_impl_t *private_key, vsc_str_t previous_card_id, vssc_error_t *error) {

    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(previous_card_id));
    VSSC_ASSERT_PTR(private_key);
    VSSC_ASSERT(vscf_private_key_is_implemented(private_key));

    return vssc_card_manager_generate_raw_card_inner(self, identity, private_key, previous_card_id, error);
}

//
//  Generates self-signed "raw card" with an optional previous card id.
//
static vssc_raw_card_t *
vssc_card_manager_generate_raw_card_inner(const vssc_card_manager_t *self, vsc_str_t identity,
        const vscf_impl_t *private_key, vsc_str_t previous_card_id, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->random);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT(vsc_str_is_valid(previous_card_id));
    VSSC_ASSERT_PTR(private_key);
    VSSC_ASSERT(vscf_private_key_is_implemented(private_key));

    //
    //  Export public key.
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    const size_t public_key_len = vscf_key_provider_exported_public_key_len(key_provider, public_key);
    vsc_buffer_t *public_key_data = vsc_buffer_new_with_capacity(public_key_len);

    const vscf_status_t export_status = vscf_key_provider_export_public_key(key_provider, public_key, public_key_data);

    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);

    if (export_status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&public_key_data);

        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_EXPORT_PUBLIC_KEY_FAILED);

        return NULL;
    }

    //
    //  Create Raw Card without signatures.
    //
    const size_t now_timestamp = vssc_unix_time_now();
    vssc_raw_card_t *raw_card = vssc_raw_card_new_with_disown(identity, &public_key_data, now_timestamp);

    if (!vsc_str_is_empty(previous_card_id)) {
        vssc_raw_card_set_previous_card_id(raw_card, previous_card_id);
    }

    //
    //  Add self-signature.
    //
    const vssc_status_t signing_status = vssc_raw_card_signer_self_sign(self->raw_card_signer, raw_card, private_key);
    if (signing_status != vssc_status_SUCCESS) {
        vssc_raw_card_destroy(&raw_card);
        VSSC_ERROR_SAFE_UPDATE(error, signing_status);
        return NULL;
    }

    return raw_card;
}

//
//  Create Card from "raw card" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card(
        const vssc_card_manager_t *self, const vssc_raw_card_t *raw_card, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->random);
    VSSC_ASSERT_PTR(self->virgil_public_key);
    VSSC_ASSERT_PTR(raw_card);

    //
    //  Import public key.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, vssc_raw_card_public_key(raw_card), &foundation_error);

    vsc_buffer_t *public_key_id = NULL;

    if (vscf_error_has_error(&foundation_error)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_IMPORT_PUBLIC_KEY_FAILED);
        goto error;
    }

    //
    //  Validated Raw Card's self-signature and virgil-signature.
    //
    const bool self_signaure_is_verified = vssc_raw_card_verifier_verify_self(raw_card, public_key);
    if (!self_signaure_is_verified) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_VERIFICATION_FAILED);
        goto error;
    }

    const bool virgil_signaure_is_verified = vssc_raw_card_verifier_verify_virgil(raw_card, self->virgil_public_key);
    if (!virgil_signaure_is_verified) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_VERIFICATION_FAILED);
        goto error;
    }

    //
    //  Create card without check of custom signatures.
    //  They should be verified outside.
    //
    public_key_id = vsc_buffer_new_with_capacity(vscf_key_provider_KEY_ID_LEN);

    foundation_error.status = vscf_key_provider_calculate_key_id(key_provider, public_key, public_key_id);

    if (vscf_error_has_error(&foundation_error)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_PRODUCE_PUBLIC_KEY_ID_FAILED);
        goto error;
    }

    vscf_key_provider_destroy(&key_provider);

    return vssc_card_new_with_disown(raw_card, &public_key_id, &public_key);

error:

    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&public_key_id);

    return NULL;
}

//
//  Create list of Cards from "raw card list" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_list_t *
vssc_card_manager_import_raw_card_list(
        const vssc_card_manager_t *self, const vssc_raw_card_list_t *raw_card_list, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(raw_card_list);

    vssc_card_list_t *cards = vssc_card_list_new();

    for (const vssc_raw_card_list_t *raw_card_it = raw_card_list;
            (raw_card_it != NULL) && vssc_raw_card_list_has_item(raw_card_it);
            raw_card_it = vssc_raw_card_list_next(raw_card_it)) {

        const vssc_raw_card_t *raw_card = vssc_raw_card_list_item(raw_card_it);

        vssc_card_t *card = vssc_card_manager_import_raw_card(self, raw_card, error);

        if (card != NULL) {
            vssc_card_list_add(cards, &card);

        } else {
            vssc_card_list_destroy(&cards);
            return NULL;
        }
    }

    return cards;
}

//
//  Create Card with expected card identifier from "raw card" and verify it.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card_with_id(
        const vssc_card_manager_t *self, const vssc_raw_card_t *raw_card, vsc_str_t card_id, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(raw_card);

    vssc_card_t *card = vssc_card_manager_import_raw_card(self, raw_card, error);
    if (NULL == card) {
        return NULL;
    }

    vsc_str_t imported_card_id = vssc_card_identifier(card);
    if (!vsc_str_equal(card_id, imported_card_id)) {
        vssc_card_destroy(&card);

        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_SERVICE_RETURNED_INVALID_CARD);

        return NULL;
    }

    return card;
}

//
//  Create Card from "raw card" with additional check which ensures
//  that Virgil Cards Service do not change self-signature.
//
//  Note, only self signature and Virgil Cards Service signatures are verified.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_manager_import_raw_card_with_initial_raw_card(const vssc_card_manager_t *self,
        const vssc_raw_card_t *raw_card, const vssc_raw_card_t *initial_raw_card, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT_PTR(initial_raw_card);


    vsc_data_t content_snapshot = vssc_raw_card_content_snapshot(raw_card);
    vsc_data_t initial_content_snapshot = vssc_raw_card_content_snapshot(initial_raw_card);

    if (!vsc_data_equal(content_snapshot, initial_content_snapshot)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_SERVICE_RETURNED_INVALID_CARD);
        return NULL;
    }

    vssc_card_t *card = vssc_card_manager_import_raw_card(self, raw_card, error);

    return card;
}
