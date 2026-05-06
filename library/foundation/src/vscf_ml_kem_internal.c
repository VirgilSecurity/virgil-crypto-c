//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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
//  //
//  //  This module contains logic for interface/implementation architecture.
//  //  Do not use this module in any part of the code.
//  //
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ml_kem_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ml_kem_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_api.h"
#include "vscf_kem.h"
#include "vscf_kem_api.h"
#include "vscf_random.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ml_kem_use_random(vscf_ml_kem_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ml_kem_take_random(vscf_ml_kem_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_ml_kem_release_random(vscf_ml_kem_t *self);

static const vscf_api_t *
vscf_ml_kem_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the  'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ML_KEM,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_ml_kem_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_ml_kem_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_ml_kem_restore_alg_info
};

//
//  Configuration of the interface API 'key alg api'.
//
static const vscf_key_alg_api_t key_alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key alg' MUST be equal to the  'vscf_api_tag_KEY_ALG'.
    //
    vscf_api_tag_KEY_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ML_KEM,
    //
    //  Generate ephemeral private key of the same type.
    //  Note, this operation might be slow.
    //
    (vscf_key_alg_api_generate_ephemeral_key_fn)vscf_ml_kem_generate_ephemeral_key,
    //
    //  Import public key from the raw binary format.
    //
    //  Return public key that is adopted and optimized to be used
    //  with this particular algorithm.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_import_public_key_fn)vscf_ml_kem_import_public_key,
    //
    //  Import public key from the raw binary format.
    //
    (vscf_key_alg_api_import_public_key_data_fn)vscf_ml_kem_import_public_key_data,
    //
    //  Export public key to the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_export_public_key_fn)vscf_ml_kem_export_public_key,
    //
    //  Return length in bytes required to hold exported public key.
    //
    (vscf_key_alg_api_exported_public_key_data_len_fn)vscf_ml_kem_exported_public_key_data_len,
    //
    //  Export public key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_export_public_key_data_fn)vscf_ml_kem_export_public_key_data,
    //
    //  Import private key from the raw binary format.
    //
    //  Return private key that is adopted and optimized to be used
    //  with this particular algorithm.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_import_private_key_fn)vscf_ml_kem_import_private_key,
    //
    //  Import private key from the raw binary format.
    //
    (vscf_key_alg_api_import_private_key_data_fn)vscf_ml_kem_import_private_key_data,
    //
    //  Export private key in the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_export_private_key_fn)vscf_ml_kem_export_private_key,
    //
    //  Return length in bytes required to hold exported private key.
    //
    (vscf_key_alg_api_exported_private_key_data_len_fn)vscf_ml_kem_exported_private_key_data_len,
    //
    //  Export private key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_export_private_key_data_fn)vscf_ml_kem_export_private_key_data,
    //
    //  Defines whether a public key can be imported or not.
    //
    vscf_ml_kem_CAN_IMPORT_PUBLIC_KEY,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_ml_kem_CAN_EXPORT_PUBLIC_KEY,
    //
    //  Define whether a private key can be imported or not.
    //
    vscf_ml_kem_CAN_IMPORT_PRIVATE_KEY,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_ml_kem_CAN_EXPORT_PRIVATE_KEY
};

//
//  Configuration of the interface API 'kem api'.
//
static const vscf_kem_api_t kem_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'kem' MUST be equal to the  'vscf_api_tag_KEM'.
    //
    vscf_api_tag_KEM,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ML_KEM,
    //
    //  Return length in bytes required to hold encapsulated shared key.
    //
    (vscf_kem_api_kem_shared_key_len_fn)vscf_ml_kem_kem_shared_key_len,
    //
    //  Return length in bytes required to hold encapsulated key.
    //
    (vscf_kem_api_kem_encapsulated_key_len_fn)vscf_ml_kem_kem_encapsulated_key_len,
    //
    //  Generate a shared key and a key encapsulated message.
    //
    (vscf_kem_api_kem_encapsulate_fn)vscf_ml_kem_kem_encapsulate,
    //
    //  Decapsulate the shared key.
    //
    (vscf_kem_api_kem_decapsulate_fn)vscf_ml_kem_kem_decapsulate
};

//
//  Compile-time known information about 'ml kem' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_ML_KEM,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ml_kem_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ml_kem_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ml_kem_delete
};

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ml_kem_use_random(vscf_ml_kem_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ml_kem_take_random(vscf_ml_kem_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_ml_kem_release_random(vscf_ml_kem_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ml_kem_init(vscf_ml_kem_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ml_kem_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_ml_kem_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ml_kem_init()'.
//
VSCF_PUBLIC void
vscf_ml_kem_cleanup(vscf_ml_kem_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_ml_kem_release_random(self);

    vscf_ml_kem_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_ml_kem_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ml_kem_t *
vscf_ml_kem_new(void) {

    vscf_ml_kem_t *self = (vscf_ml_kem_t *) vscf_alloc(sizeof (vscf_ml_kem_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ml_kem_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ml_kem_new()'.
//
VSCF_PUBLIC void
vscf_ml_kem_delete(vscf_ml_kem_t *self) {

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

    vscf_ml_kem_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ml_kem_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ml_kem_destroy(vscf_ml_kem_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ml_kem_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ml_kem_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_ml_kem_t *
vscf_ml_kem_shallow_copy(vscf_ml_kem_t *self) {

    // Proxy to the parent implementation.
    return (vscf_ml_kem_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_ml_kem_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ml_kem_init_ctx(vscf_ml_kem_t *self) {

    VSCF_UNUSED(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ml_kem_cleanup_ctx(vscf_ml_kem_t *self) {

    VSCF_UNUSED(self);
}

//
//  Return size of 'vscf_ml_kem_t' type.
//
VSCF_PUBLIC size_t
vscf_ml_kem_impl_size(void) {

    return sizeof (vscf_ml_kem_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ml_kem_impl(vscf_ml_kem_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ml_kem_impl_const(const vscf_ml_kem_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_ml_kem_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
        return (const vscf_api_t *)                 &alg_api;
        case vscf_api_tag_KEM:
        return (const vscf_api_t *)                 &kem_api;
        case vscf_api_tag_KEY_ALG:
        return (const vscf_api_t *)                 &key_alg_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
