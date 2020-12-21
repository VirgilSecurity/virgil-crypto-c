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
//  Class responsible for signing "raw card".
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_raw_card_signer.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_raw_card_signer_defs.h"

#include <virgil/crypto/foundation/vscf_signer.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_private_key.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_signer_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_signer_init_ctx(vssc_raw_card_signer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_signer_cleanup_ctx(vssc_raw_card_signer_t *self);

//
//  Create Signer with a default configuration.
//
static vscf_signer_t *
vssc_raw_card_signer_create_signer(const vssc_raw_card_signer_t *self);

//
//  Identifier of self-signature.
//
static const char k_self_signer_id_chars[] = "self";

//
//  Identifier of self-signature.
//
static const vsc_str_t k_self_signer_id = {
    k_self_signer_id_chars,
    sizeof(k_self_signer_id_chars) - 1
};

//
//  Identifier of Virgil signature.
//
static const char k_virgil_signer_id_chars[] = "virgil";

//
//  Identifier of Virgil signature.
//
static const vsc_str_t k_virgil_signer_id = {
    k_virgil_signer_id_chars,
    sizeof(k_virgil_signer_id_chars) - 1
};

//
//  Return size of 'vssc_raw_card_signer_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_signer_ctx_size(void) {

    return sizeof(vssc_raw_card_signer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_signer_init(vssc_raw_card_signer_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signer_t));

    self->refcnt = 1;

    vssc_raw_card_signer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_signer_cleanup(vssc_raw_card_signer_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_raw_card_signer_release_random(self);

    vssc_raw_card_signer_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signer_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_signer_t *
vssc_raw_card_signer_new(void) {

    vssc_raw_card_signer_t *self = (vssc_raw_card_signer_t *) vssc_alloc(sizeof (vssc_raw_card_signer_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signer_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_signer_delete(const vssc_raw_card_signer_t *self) {

    vssc_raw_card_signer_t *local_self = (vssc_raw_card_signer_t *)self;

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

    vssc_raw_card_signer_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_signer_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_signer_destroy(vssc_raw_card_signer_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_raw_card_signer_t *self = *self_ref;
    *self_ref = NULL;

    vssc_raw_card_signer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_signer_t *
vssc_raw_card_signer_shallow_copy(vssc_raw_card_signer_t *self) {

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
VSSC_PUBLIC const vssc_raw_card_signer_t *
vssc_raw_card_signer_shallow_copy_const(const vssc_raw_card_signer_t *self) {

    return vssc_raw_card_signer_shallow_copy((vssc_raw_card_signer_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSC_PUBLIC void
vssc_raw_card_signer_use_random(vssc_raw_card_signer_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSC_PUBLIC void
vssc_raw_card_signer_take_random(vssc_raw_card_signer_t *self, vscf_impl_t *random) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(random);
    VSSC_ASSERT(self->random == NULL);

    VSSC_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSSC_PUBLIC void
vssc_raw_card_signer_release_random(vssc_raw_card_signer_t *self) {

    VSSC_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_signer_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_signer_init_ctx(vssc_raw_card_signer_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_signer_cleanup_ctx(vssc_raw_card_signer_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Adds signature to given "raw card" with provided signer and private key.
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card, vsc_str_t signer_id,
        const vscf_impl_t *private_key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->random);
    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT_PTR(private_key);
    VSSC_ASSERT(vscf_private_key_is_implemented(private_key));

    vscf_signer_t *signer = vssc_raw_card_signer_create_signer(self);

    vscf_signer_reset(signer);
    vscf_signer_append_data(signer, vssc_raw_card_content_snapshot(raw_card));

    const size_t signature_len = vscf_signer_signature_len(signer, private_key);
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(signature_len);

    const vscf_status_t signing_status = vscf_signer_sign(signer, private_key, signature);

    vscf_signer_destroy(&signer);

    if (signing_status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&signature);
        return vssc_status_PRODUCE_SIGNATURE_FAILED;
    }

    vssc_raw_card_signature_t *raw_card_signature =
            vssc_raw_card_signature_new_with_signature_disown(signer_id, &signature);

    vssc_raw_card_add_signature_disown(raw_card, &raw_card_signature);

    return vssc_status_SUCCESS;
}

//
//  Adds self-signature to given "raw card".
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_self_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card,
        const vscf_impl_t *private_key) {

    return vssc_raw_card_signer_sign(self, raw_card, k_self_signer_id, private_key);
}

//
//  Adds Virgil Signature to given "raw card".
//
VSSC_PUBLIC vssc_status_t
vssc_raw_card_signer_virgil_sign(const vssc_raw_card_signer_t *self, vssc_raw_card_t *raw_card,
        const vscf_impl_t *private_key) {

    return vssc_raw_card_signer_sign(self, raw_card, k_virgil_signer_id, private_key);
}

//
//  Create Signer with a default configuration.
//
static vscf_signer_t *
vssc_raw_card_signer_create_signer(const vssc_raw_card_signer_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->random);

    vscf_signer_t *signer = vscf_signer_new();
    vscf_signer_take_hash(signer, vscf_sha512_impl(vscf_sha512_new()));
    vscf_signer_use_random(signer, (vscf_impl_t *)self->random);

    return signer;
}
