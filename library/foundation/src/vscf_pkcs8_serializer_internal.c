//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "vscf_pkcs8_serializer_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_pkcs8_serializer_impl.h"
#include "vscf_key_serializer.h"
#include "vscf_key_serializer_api.h"
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
vscf_pkcs8_serializer_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'key serializer api'.
//
static const vscf_key_serializer_api_t key_serializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key_serializer' MUST be equal to the 'vscf_api_tag_KEY_SERIALIZER'.
    //
    vscf_api_tag_KEY_SERIALIZER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_PKCS8_SERIALIZER,
    //
    //  Calculate buffer size enough to hold serialized public key.
    //
    //  Precondition: public key must be exportable.
    //
    (vscf_key_serializer_api_serialized_public_key_len_fn)vscf_pkcs8_serializer_serialized_public_key_len,
    //
    //  Serialize given public key to an interchangeable format.
    //
    //  Precondition: public key must be exportable.
    //
    (vscf_key_serializer_api_serialize_public_key_fn)vscf_pkcs8_serializer_serialize_public_key,
    //
    //  Calculate buffer size enough to hold serialized private key.
    //
    //  Precondition: private key must be exportable.
    //
    (vscf_key_serializer_api_serialized_private_key_len_fn)vscf_pkcs8_serializer_serialized_private_key_len,
    //
    //  Serialize given private key to an interchangeable format.
    //
    //  Precondition: private key must be exportable.
    //
    (vscf_key_serializer_api_serialize_private_key_fn)vscf_pkcs8_serializer_serialize_private_key
};

//
//  Compile-time known information about 'pkcs8 serializer' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_PKCS8_SERIALIZER,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_pkcs8_serializer_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_pkcs8_serializer_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_pkcs8_serializer_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_pkcs8_serializer_init(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);

    vscf_zeroize(pkcs8_serializer_impl, sizeof(vscf_pkcs8_serializer_impl_t));

    pkcs8_serializer_impl->info = &info;
    pkcs8_serializer_impl->refcnt = 1;

    vscf_pkcs8_serializer_init_ctx(pkcs8_serializer_impl);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_serializer_init()'.
//
VSCF_PUBLIC void
vscf_pkcs8_serializer_cleanup(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    if (pkcs8_serializer_impl == NULL || pkcs8_serializer_impl->info == NULL) {
        return;
    }

    if (pkcs8_serializer_impl->refcnt == 0) {
        return;
    }

    if (--pkcs8_serializer_impl->refcnt > 0) {
        return;
    }

    vscf_pkcs8_serializer_cleanup_ctx(pkcs8_serializer_impl);

    vscf_zeroize(pkcs8_serializer_impl, sizeof(vscf_pkcs8_serializer_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pkcs8_serializer_impl_t *
vscf_pkcs8_serializer_new(void) {

    vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl = (vscf_pkcs8_serializer_impl_t *) vscf_alloc(sizeof (vscf_pkcs8_serializer_impl_t));
    VSCF_ASSERT_ALLOC(pkcs8_serializer_impl);

    vscf_pkcs8_serializer_init(pkcs8_serializer_impl);

    return pkcs8_serializer_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_serializer_new()'.
//
VSCF_PUBLIC void
vscf_pkcs8_serializer_delete(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    vscf_pkcs8_serializer_cleanup(pkcs8_serializer_impl);

    if (pkcs8_serializer_impl && (pkcs8_serializer_impl->refcnt == 0)) {
        vscf_dealloc(pkcs8_serializer_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_serializer_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pkcs8_serializer_destroy(vscf_pkcs8_serializer_impl_t **pkcs8_serializer_impl_ref) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl_ref);

    vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl = *pkcs8_serializer_impl_ref;
    *pkcs8_serializer_impl_ref = NULL;

    vscf_pkcs8_serializer_delete(pkcs8_serializer_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_pkcs8_serializer_impl_t *
vscf_pkcs8_serializer_copy(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    // Proxy to the parent implementation.
    return (vscf_pkcs8_serializer_impl_t *)vscf_impl_copy((vscf_impl_t *)pkcs8_serializer_impl);
}

//
//  Return size of 'vscf_pkcs8_serializer_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_pkcs8_serializer_impl_size(void) {

    return sizeof (vscf_pkcs8_serializer_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs8_serializer_impl(vscf_pkcs8_serializer_impl_t *pkcs8_serializer_impl) {

    VSCF_ASSERT_PTR(pkcs8_serializer_impl);
    return (vscf_impl_t *)(pkcs8_serializer_impl);
}

static const vscf_api_t *
vscf_pkcs8_serializer_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_KEY_SERIALIZER:
            return (const vscf_api_t *) &key_serializer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
