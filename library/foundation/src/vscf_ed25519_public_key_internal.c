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

#include "vscf_ed25519_public_key_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ed25519_public_key_defs.h"
#include "vscf_key.h"
#include "vscf_key_api.h"
#include "vscf_verify.h"
#include "vscf_verify_api.h"
#include "vscf_public_key.h"
#include "vscf_public_key_api.h"
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
vscf_ed25519_public_key_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'key api'.
//
static const vscf_key_api_t key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key' MUST be equal to the 'vscf_api_tag_KEY'.
    //
    vscf_api_tag_KEY,
    //
    //  Return implemented asymmetric key algorithm type.
    //
    (vscf_key_api_alg_fn)vscf_ed25519_public_key_alg,
    //
    //  Length of the key in bytes.
    //
    (vscf_key_api_key_len_fn)vscf_ed25519_public_key_key_len,
    //
    //  Length of the key in bits.
    //
    (vscf_key_api_key_bitlen_fn)vscf_ed25519_public_key_key_bitlen
};

//
//  Configuration of the interface API 'verify api'.
//
static const vscf_verify_api_t verify_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'verify' MUST be equal to the 'vscf_api_tag_VERIFY'.
    //
    vscf_api_tag_VERIFY,
    //
    //  Verify data with given public key and signature.
    //
    (vscf_verify_api_verify_fn)vscf_ed25519_public_key_verify
};

//
//  Configuration of the interface API 'public key api'.
//
static const vscf_public_key_api_t public_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'public_key' MUST be equal to the 'vscf_api_tag_PUBLIC_KEY'.
    //
    vscf_api_tag_PUBLIC_KEY,
    //
    //  Link to the inherited interface API 'key'.
    //
    &key_api,
    //
    //  Export public key in the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_public_key_api_export_public_key_fn)vscf_ed25519_public_key_export_public_key,
    //
    //  Return length in bytes required to hold exported public key.
    //
    (vscf_public_key_api_exported_public_key_len_fn)vscf_ed25519_public_key_exported_public_key_len,
    //
    //  Import public key from the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_public_key_api_import_public_key_fn)vscf_ed25519_public_key_import_public_key,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_ed25519_public_key_CAN_EXPORT_PUBLIC_KEY,
    //
    //  Defines whether a public key can be imported or not.
    //
    vscf_ed25519_public_key_CAN_IMPORT_PUBLIC_KEY
};

//
//  Compile-time known information about 'ed25519 public key' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ed25519_public_key_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ed25519_public_key_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ed25519_public_key_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ed25519_public_key_init(vscf_ed25519_public_key_t *ed25519_public_key) {

    VSCF_ASSERT_PTR(ed25519_public_key);

    vscf_zeroize(ed25519_public_key, sizeof(vscf_ed25519_public_key_t));

    ed25519_public_key->info = &info;
    ed25519_public_key->refcnt = 1;

    vscf_ed25519_public_key_init_ctx(ed25519_public_key);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ed25519_public_key_init()'.
//
VSCF_PUBLIC void
vscf_ed25519_public_key_cleanup(vscf_ed25519_public_key_t *ed25519_public_key) {

    if (ed25519_public_key == NULL || ed25519_public_key->info == NULL) {
        return;
    }

    if (ed25519_public_key->refcnt == 0) {
        return;
    }

    if (--ed25519_public_key->refcnt > 0) {
        return;
    }

    vscf_ed25519_public_key_cleanup_ctx(ed25519_public_key);

    vscf_zeroize(ed25519_public_key, sizeof(vscf_ed25519_public_key_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ed25519_public_key_t *
vscf_ed25519_public_key_new(void) {

    vscf_ed25519_public_key_t *ed25519_public_key = (vscf_ed25519_public_key_t *) vscf_alloc(sizeof (vscf_ed25519_public_key_t));
    VSCF_ASSERT_ALLOC(ed25519_public_key);

    vscf_ed25519_public_key_init(ed25519_public_key);

    return ed25519_public_key;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_public_key_new()'.
//
VSCF_PUBLIC void
vscf_ed25519_public_key_delete(vscf_ed25519_public_key_t *ed25519_public_key) {

    vscf_ed25519_public_key_cleanup(ed25519_public_key);

    if (ed25519_public_key && (ed25519_public_key->refcnt == 0)) {
        vscf_dealloc(ed25519_public_key);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_public_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ed25519_public_key_destroy(vscf_ed25519_public_key_t **ed25519_public_key_ref) {

    VSCF_ASSERT_PTR(ed25519_public_key_ref);

    vscf_ed25519_public_key_t *ed25519_public_key = *ed25519_public_key_ref;
    *ed25519_public_key_ref = NULL;

    vscf_ed25519_public_key_delete(ed25519_public_key);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_ed25519_public_key_t *
vscf_ed25519_public_key_shallow_copy(vscf_ed25519_public_key_t *ed25519_public_key) {

    // Proxy to the parent implementation.
    return (vscf_ed25519_public_key_t *)vscf_impl_shallow_copy((vscf_impl_t *)ed25519_public_key);
}

//
//  Return size of 'vscf_ed25519_public_key_t' type.
//
VSCF_PUBLIC size_t
vscf_ed25519_public_key_impl_size(void) {

    return sizeof (vscf_ed25519_public_key_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_public_key_impl(vscf_ed25519_public_key_t *ed25519_public_key) {

    VSCF_ASSERT_PTR(ed25519_public_key);
    return (vscf_impl_t *)(ed25519_public_key);
}

static const vscf_api_t *
vscf_ed25519_public_key_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_KEY:
            return (const vscf_api_t *) &key_api;
        case vscf_api_tag_PUBLIC_KEY:
            return (const vscf_api_t *) &public_key_api;
        case vscf_api_tag_VERIFY:
            return (const vscf_api_t *) &verify_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
