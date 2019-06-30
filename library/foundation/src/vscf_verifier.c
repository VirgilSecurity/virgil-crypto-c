//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  Verify data of any size.
//  Compatible with the class "signer".
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_verifier.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_verifier_defs.h"
#include "vscf_alg.h"
#include "vscf_hash.h"
#include "vscf_key_signer.h"
#include "vscf_asn1rd.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"
#include "vscf_public_key.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_verifier_init_ctx(vscf_verifier_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_verifier_cleanup_ctx(vscf_verifier_t *self);

//
//  Return size of 'vscf_verifier_t'.
//
VSCF_PUBLIC size_t
vscf_verifier_ctx_size(void) {

    return sizeof(vscf_verifier_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_verifier_init(vscf_verifier_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_verifier_t));

    self->refcnt = 1;

    vscf_verifier_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_verifier_cleanup(vscf_verifier_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_verifier_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_verifier_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_verifier_t *
vscf_verifier_new(void) {

    vscf_verifier_t *self = (vscf_verifier_t *) vscf_alloc(sizeof (vscf_verifier_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_verifier_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_verifier_delete(vscf_verifier_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_verifier_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_verifier_new ()'.
//
VSCF_PUBLIC void
vscf_verifier_destroy(vscf_verifier_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_verifier_t *self = *self_ref;
    *self_ref = NULL;

    vscf_verifier_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_verifier_t *
vscf_verifier_shallow_copy(vscf_verifier_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_verifier_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_verifier_init_ctx(vscf_verifier_t *self) {

    VSCF_ASSERT_PTR(self);

    self->asn1rd = vscf_asn1rd_new();
    self->alg_info_der_deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_use_asn1_reader(self->alg_info_der_deserializer, vscf_asn1rd_impl(self->asn1rd));
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_verifier_cleanup_ctx(vscf_verifier_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->hash);
    vscf_asn1rd_destroy(&self->asn1rd);
    vscf_alg_info_der_deserializer_destroy(&self->alg_info_der_deserializer);
    vsc_buffer_destroy(&self->raw_signature);
}

//
//  Start verifying a signature.
//
VSCF_PUBLIC vscf_status_t
vscf_verifier_reset(vscf_verifier_t *self, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->asn1rd);
    VSCF_ASSERT_PTR(self->alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(signature));

    vscf_impl_destroy(&self->hash);
    vsc_buffer_destroy(&self->raw_signature);

    //
    // Unrap signature from the ASN.1 structure.
    //
    vscf_asn1rd_reset(self->asn1rd, signature);

    vscf_asn1rd_read_sequence(self->asn1rd);
    vscf_impl_t *hash_alg_info =
            vscf_alg_info_der_deserializer_deserialize_inplace(self->alg_info_der_deserializer, NULL);
    vsc_data_t raw_signature = vscf_asn1rd_read_octet_str(self->asn1rd);

    if (vscf_asn1rd_has_error(self->asn1rd)) {
        vscf_impl_destroy(&hash_alg_info);
        return vscf_status_ERROR_BAD_SIGNATURE;
    }

    self->hash = vscf_alg_factory_create_hash_from_info(hash_alg_info);
    self->raw_signature = vsc_buffer_new_with_data(raw_signature);

    vscf_hash_start(self->hash);

    vscf_impl_destroy(&hash_alg_info);

    return vscf_status_SUCCESS;
}

//
//  Add given data to the signed data.
//
VSCF_PUBLIC void
vscf_verifier_append_data(vscf_verifier_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_hash_update(self->hash, data);
}

//
//  Verify accumulated data.
//
VSCF_PUBLIC bool
vscf_verifier_verify(vscf_verifier_t *self, vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(self->raw_signature);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    //
    //  Get digest.
    //
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_hash_digest_len(vscf_hash_api(self->hash)));
    vscf_hash_finish(self->hash, digest);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_key(public_key, NULL, &error);
    VSCF_ASSERT(vscf_error_has_error(&error));
    VSCF_ASSERT(vscf_key_signer_is_implemented(key_alg));

    bool is_valid = vscf_key_signer_verify_hash(key_alg, public_key, vscf_alg_alg_id(self->hash),
            vsc_buffer_data(digest), vsc_buffer_data(self->raw_signature));

    vscf_impl_destroy(&key_alg);
    vsc_buffer_destroy(&digest);

    return is_valid;
}
