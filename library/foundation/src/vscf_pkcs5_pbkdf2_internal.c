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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs5_pbkdf2_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_pkcs5_pbkdf2_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_kdf.h"
#include "vscf_kdf_api.h"
#include "vscf_salted_kdf.h"
#include "vscf_salted_kdf_api.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_pkcs5_pbkdf2_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the 'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PKCS5_PBKDF2,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_pkcs5_pbkdf2_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_pkcs5_pbkdf2_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_pkcs5_pbkdf2_restore_alg_info
};

//
//  Configuration of the interface API 'kdf api'.
//
static const vscf_kdf_api_t kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'kdf' MUST be equal to the 'vscf_api_tag_KDF'.
    //
    vscf_api_tag_KDF,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PKCS5_PBKDF2,
    //
    //  Derive key of the requested length from the given data.
    //
    (vscf_kdf_api_derive_fn)vscf_pkcs5_pbkdf2_derive
};

//
//  Configuration of the interface API 'salted kdf api'.
//
static const vscf_salted_kdf_api_t salted_kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'salted_kdf' MUST be equal to the 'vscf_api_tag_SALTED_KDF'.
    //
    vscf_api_tag_SALTED_KDF,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PKCS5_PBKDF2,
    //
    //  Link to the inherited interface API 'kdf'.
    //
    &kdf_api,
    //
    //  Prepare algorithm to derive new key.
    //
    (vscf_salted_kdf_api_reset_fn)vscf_pkcs5_pbkdf2_reset,
    //
    //  Setup application specific information (optional).
    //  Can be empty.
    //
    (vscf_salted_kdf_api_set_info_fn)vscf_pkcs5_pbkdf2_set_info
};

//
//  Compile-time known information about 'pkcs5 pbkdf2' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_PKCS5_PBKDF2,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_pkcs5_pbkdf2_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_pkcs5_pbkdf2_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_pkcs5_pbkdf2_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_init(vscf_pkcs5_pbkdf2_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_pkcs5_pbkdf2_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_pkcs5_pbkdf2_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_init()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_cleanup(vscf_pkcs5_pbkdf2_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_pkcs5_pbkdf2_release_hmac(self);

    vscf_pkcs5_pbkdf2_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_pkcs5_pbkdf2_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pkcs5_pbkdf2_t *
vscf_pkcs5_pbkdf2_new(void) {

    vscf_pkcs5_pbkdf2_t *self = (vscf_pkcs5_pbkdf2_t *) vscf_alloc(sizeof (vscf_pkcs5_pbkdf2_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_pkcs5_pbkdf2_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_new()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_delete(const vscf_pkcs5_pbkdf2_t *self) {

    vscf_pkcs5_pbkdf2_t *local_self = (vscf_pkcs5_pbkdf2_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_pkcs5_pbkdf2_cleanup(local_self);

    vscf_dealloc(local_self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_destroy(vscf_pkcs5_pbkdf2_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_pkcs5_pbkdf2_t *self = *self_ref;
    *self_ref = NULL;

    vscf_pkcs5_pbkdf2_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_pkcs5_pbkdf2_t *
vscf_pkcs5_pbkdf2_shallow_copy(vscf_pkcs5_pbkdf2_t *self) {

    // Proxy to the parent implementation.
    return (vscf_pkcs5_pbkdf2_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Copy given implementation context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_pkcs5_pbkdf2_t *
vscf_pkcs5_pbkdf2_shallow_copy_const(const vscf_pkcs5_pbkdf2_t *self) {

    // Proxy to the parent implementation.
    return (vscf_pkcs5_pbkdf2_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_pkcs5_pbkdf2_t' type.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbkdf2_impl_size(void) {

    return sizeof (vscf_pkcs5_pbkdf2_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs5_pbkdf2_impl(vscf_pkcs5_pbkdf2_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_pkcs5_pbkdf2_impl_const(const vscf_pkcs5_pbkdf2_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'mac' with shared ownership.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_use_hmac(vscf_pkcs5_pbkdf2_t *self, vscf_impl_t *hmac) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT(self->hmac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(hmac));

    self->hmac = vscf_impl_shallow_copy(hmac);
}

//
//  Setup dependency to the interface 'mac' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_take_hmac(vscf_pkcs5_pbkdf2_t *self, vscf_impl_t *hmac) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT(self->hmac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(hmac));

    self->hmac = hmac;
}

//
//  Release dependency to the interface 'mac'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_release_hmac(vscf_pkcs5_pbkdf2_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->hmac);
}

static const vscf_api_t *
vscf_pkcs5_pbkdf2_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_KDF:
            return (const vscf_api_t *) &kdf_api;
        case vscf_api_tag_SALTED_KDF:
            return (const vscf_api_t *) &salted_kdf_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
