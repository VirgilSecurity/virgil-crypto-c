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
//  Represent Virgil Card.
//
//  Virgil Card is a central entity of Virgil Cards Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_card.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_card_defs.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/foundation/private/vscf_sha512_defs.h>
#include <virgil/crypto/foundation/vscf_binary.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vssc_card_IDENTIFIER_BINARY_LEN = 32,
    vssc_card_IDENTIFIER_HEX_LEN = 64
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_init_ctx(vssc_card_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_cleanup_ctx(vssc_card_t *self);

//
//  Create Virgil Card with mandatory properties.
//
static void
vssc_card_init_ctx_with(vssc_card_t *self, const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key);

//
//  Create Virgil Card with mandatory properties.
//
static void
vssc_card_init_ctx_with_disown(vssc_card_t *self, vssc_raw_card_t **raw_card_ref, vscf_impl_t **public_key_ref);

//
//  Perfrom derivation of the public key identifier from its binary representation.
//
static void
vssc_card_derive_identifier(vssc_card_t *self);

//
//  Return size of 'vssc_card_t'.
//
VSSC_PUBLIC size_t
vssc_card_ctx_size(void) {

    return sizeof(vssc_card_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_init(vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_t));

    self->refcnt = 1;

    vssc_card_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_cleanup(vssc_card_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_card_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_card_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_new(void) {

    vssc_card_t *self = (vssc_card_t *) vssc_alloc(sizeof (vssc_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Virgil Card with mandatory properties.
//
VSSC_PUBLIC void
vssc_card_init_with(vssc_card_t *self, const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_t));

    self->refcnt = 1;

    vssc_card_init_ctx_with(self, raw_card, public_key);
}

//
//  Allocate class context and perform it's initialization.
//  Create Virgil Card with mandatory properties.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_new_with(const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key) {

    vssc_card_t *self = (vssc_card_t *) vssc_alloc(sizeof (vssc_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_init_with(self, raw_card, public_key);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Virgil Card with mandatory properties.
//
VSSC_PRIVATE void
vssc_card_init_with_disown(vssc_card_t *self, vssc_raw_card_t **raw_card_ref, vscf_impl_t **public_key_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_t));

    self->refcnt = 1;

    vssc_card_init_ctx_with_disown(self, raw_card_ref, public_key_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create Virgil Card with mandatory properties.
//
VSSC_PRIVATE vssc_card_t *
vssc_card_new_with_disown(vssc_raw_card_t **raw_card_ref, vscf_impl_t **public_key_ref) {

    vssc_card_t *self = (vssc_card_t *) vssc_alloc(sizeof (vssc_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_init_with_disown(self, raw_card_ref, public_key_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_delete(const vssc_card_t *self) {

    vssc_card_t *local_self = (vssc_card_t *)self;

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

    vssc_card_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_new ()'.
//
VSSC_PUBLIC void
vssc_card_destroy(vssc_card_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_card_t *self = *self_ref;
    *self_ref = NULL;

    vssc_card_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_t *
vssc_card_shallow_copy(vssc_card_t *self) {

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
VSSC_PUBLIC const vssc_card_t *
vssc_card_shallow_copy_const(const vssc_card_t *self) {

    return vssc_card_shallow_copy((vssc_card_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_init_ctx(vssc_card_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_cleanup_ctx(vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_delete(self->identifier);
    vssc_raw_card_delete(self->raw_card);
    vscf_impl_delete(self->public_key);
    vssc_card_delete(self->previous_card);
}

//
//  Create Virgil Card with mandatory properties.
//
static void
vssc_card_init_ctx_with(vssc_card_t *self, const vssc_raw_card_t *raw_card, const vscf_impl_t *public_key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(raw_card);
    VSSC_ASSERT_PTR(public_key);
    VSSC_ASSERT_PTR(vscf_public_key_is_implemented(public_key));

    self->raw_card = vssc_raw_card_shallow_copy_const(raw_card);
    self->public_key = vscf_impl_shallow_copy_const(public_key);

    vssc_card_derive_identifier(self);

    VSSC_ASSERT_PTR(self->identifier);
}

//
//  Create Virgil Card with mandatory properties.
//
static void
vssc_card_init_ctx_with_disown(vssc_card_t *self, vssc_raw_card_t **raw_card_ref, vscf_impl_t **public_key_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(raw_card_ref);
    VSSC_ASSERT_REF(public_key_ref);
    VSSC_ASSERT_PTR(vscf_public_key_is_implemented(*public_key_ref));

    self->raw_card = *raw_card_ref;
    self->public_key = *public_key_ref;

    *raw_card_ref = NULL;
    *public_key_ref = NULL;

    vssc_card_derive_identifier(self);

    VSSC_ASSERT_PTR(self->identifier);
}

//
//  Set previous Card.
//
VSSC_PUBLIC void
vssc_card_set_previous_card(vssc_card_t *self, const vssc_card_t *previous_card) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(previous_card);

    self->previous_card = vssc_card_shallow_copy_const(previous_card);
}

//
//  Set previous Card.
//
VSSC_PRIVATE void
vssc_card_set_previous_card_disown(vssc_card_t *self, vssc_card_t **previous_card_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(previous_card_ref);

    self->previous_card = *previous_card_ref;

    *previous_card_ref = NULL;
}

//
//  Return Card unique identifier.
//
VSSC_PUBLIC vsc_str_t
vssc_card_identifier(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->identifier);

    return vsc_str_buffer_str(self->identifier);
}

//
//  Return Card identity.
//
VSSC_PUBLIC vsc_str_t
vssc_card_identity(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_identity(self->raw_card);
}

//
//  Return Card public key.
//
VSSC_PUBLIC const vscf_impl_t *
vssc_card_public_key(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->public_key);

    return self->public_key;
}

//
//  Return Card version.
//
VSSC_PUBLIC vsc_str_t
vssc_card_version(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_version(self->raw_card);
}

//
//  Return timestamp of Card creation.
//
VSSC_PUBLIC size_t
vssc_card_created_at(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_created_at(self->raw_card);
}

//
//  Return Card content snapshot.
//
VSSC_PUBLIC vsc_data_t
vssc_card_content_snapshot(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_content_snapshot(self->raw_card);
}

//
//  Return whether Card is outdated or not.
//
VSSC_PUBLIC bool
vssc_card_is_outdated(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_is_outdated(self->raw_card);
    ;
}

//
//  Return identifier of previous card if exists.
//
VSSC_PUBLIC vsc_str_t
vssc_card_previous_card_id(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_previous_card_id(self->raw_card);
}

//
//  Return whether previous card exists or not.
//
VSSC_PUBLIC bool
vssc_card_has_previous_card(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->previous_card != NULL;
}

//
//  Return previous card if exists, NULL otherwise.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_previous_card(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vssc_card_has_previous_card(self));

    return self->previous_card;
}

//
//  Return Card signatures,
//
VSSC_PUBLIC const vssc_raw_card_signature_list_t *
vssc_card_signatures(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return vssc_raw_card_signatures(self->raw_card);
}

//
//  Return raw card.
//
VSSC_PUBLIC const vssc_raw_card_t *
vssc_card_get_raw_card(const vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    return self->raw_card;
}

//
//  Perfrom derivation of the public key identifier from its binary representation.
//
static void
vssc_card_derive_identifier(vssc_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->raw_card);

    VSSC_ASSERT(vscf_sha512_DIGEST_LEN >= vssc_card_IDENTIFIER_BINARY_LEN);

    if (NULL == self->identifier) {
        self->identifier = vsc_str_buffer_new_with_capacity(vssc_card_IDENTIFIER_HEX_LEN);
    } else {
        vsc_str_buffer_reset(self->identifier);
    }

    //
    //  1. SHA512(CONTENT_SNAPSHOT)
    //
    byte digest[vscf_sha512_DIGEST_LEN] = {0x00};
    vsc_buffer_t digest_buf;
    vsc_buffer_init(&digest_buf);
    vsc_buffer_use(&digest_buf, digest, vscf_sha512_DIGEST_LEN);

    vsc_data_t card_snapshot = vssc_raw_card_content_snapshot(self->raw_card);
    vscf_sha512_hash(card_snapshot, &digest_buf);

    //
    //  2. SHA512(CONTENT_SNAPSHOT) [:256]
    //
    vsc_data_t identifier_binary = vsc_data_slice_beg(vsc_buffer_data(&digest_buf), 0, vssc_card_IDENTIFIER_BINARY_LEN);

    //
    //  3. HEX(SHA512(CONTENT_SNAPSHOT) [:256])
    //
    vscf_binary_to_hex(identifier_binary, self->identifier);

    vsc_buffer_cleanup(&digest_buf);
}
