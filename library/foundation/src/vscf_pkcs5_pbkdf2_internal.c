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
#include "vscf_defaults.h"
#include "vscf_defaults_api.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_kdf.h"
#include "vscf_kdf_api.h"
#include "vscf_salted_kdf.h"
#include "vscf_salted_kdf_api.h"
#include "vscf_mac.h"
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
//  Configuration of the interface API 'defaults api'.
//
static const vscf_defaults_api_t defaults_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'defaults' MUST be equal to the 'vscf_api_tag_DEFAULTS'.
    //
    vscf_api_tag_DEFAULTS,
    //
    //  Setup predefined values to the uninitialized class dependencies.
    //
    (vscf_defaults_api_setup_defaults_fn)vscf_pkcs5_pbkdf2_setup_defaults
};

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
vscf_pkcs5_pbkdf2_init(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vscf_zeroize(pkcs5_pbkdf2, sizeof(vscf_pkcs5_pbkdf2_t));

    pkcs5_pbkdf2->info = &info;
    pkcs5_pbkdf2->refcnt = 1;

    vscf_pkcs5_pbkdf2_init_ctx(pkcs5_pbkdf2);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_init()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_cleanup(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    if (pkcs5_pbkdf2 == NULL || pkcs5_pbkdf2->info == NULL) {
        return;
    }

    if (pkcs5_pbkdf2->refcnt == 0) {
        return;
    }

    if (--pkcs5_pbkdf2->refcnt > 0) {
        return;
    }

    vscf_pkcs5_pbkdf2_release_hmac(pkcs5_pbkdf2);

    vscf_pkcs5_pbkdf2_cleanup_ctx(pkcs5_pbkdf2);

    vscf_zeroize(pkcs5_pbkdf2, sizeof(vscf_pkcs5_pbkdf2_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pkcs5_pbkdf2_t *
vscf_pkcs5_pbkdf2_new(void) {

    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = (vscf_pkcs5_pbkdf2_t *) vscf_alloc(sizeof (vscf_pkcs5_pbkdf2_t));
    VSCF_ASSERT_ALLOC(pkcs5_pbkdf2);

    vscf_pkcs5_pbkdf2_init(pkcs5_pbkdf2);

    return pkcs5_pbkdf2;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_new()'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_delete(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    vscf_pkcs5_pbkdf2_cleanup(pkcs5_pbkdf2);

    if (pkcs5_pbkdf2 && (pkcs5_pbkdf2->refcnt == 0)) {
        vscf_dealloc(pkcs5_pbkdf2);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs5_pbkdf2_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_destroy(vscf_pkcs5_pbkdf2_t **pkcs5_pbkdf2_ref) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2_ref);

    vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2 = *pkcs5_pbkdf2_ref;
    *pkcs5_pbkdf2_ref = NULL;

    vscf_pkcs5_pbkdf2_delete(pkcs5_pbkdf2);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_pkcs5_pbkdf2_t *
vscf_pkcs5_pbkdf2_shallow_copy(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    // Proxy to the parent implementation.
    return (vscf_pkcs5_pbkdf2_t *)vscf_impl_shallow_copy((vscf_impl_t *)pkcs5_pbkdf2);
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
vscf_pkcs5_pbkdf2_impl(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    return (vscf_impl_t *)(pkcs5_pbkdf2);
}

//
//  Setup dependency to the interface 'mac' with shared ownership.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_use_hmac(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, vscf_impl_t *hmac) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2->hmac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(hmac));

    pkcs5_pbkdf2->hmac = vscf_impl_shallow_copy(hmac);
}

//
//  Setup dependency to the interface 'mac' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_take_hmac(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, vscf_impl_t *hmac) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2->hmac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(hmac));

    pkcs5_pbkdf2->hmac = hmac;
}

//
//  Release dependency to the interface 'mac'.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_release_hmac(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    vscf_impl_destroy(&pkcs5_pbkdf2->hmac);
}

static const vscf_api_t *
vscf_pkcs5_pbkdf2_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_DEFAULTS:
            return (const vscf_api_t *) &defaults_api;
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
