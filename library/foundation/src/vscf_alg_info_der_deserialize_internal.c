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

#include "vscf_alg_info_der_deserialize_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_alg_info_der_deserialize_impl.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_alg_info_der_deserializer_api.h"
#include "vscf_asn1_reader.h"
#include "vscf_alg_info.h"
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
vscf_alg_info_der_deserialize_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg info der deserializer api'.
//
static const vscf_alg_info_der_deserializer_api_t alg_info_der_deserializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg_info_der_deserializer' MUST be equal to the 'vscf_api_tag_ALG_INFO_DER_DESERIALIZER'.
    //
    vscf_api_tag_ALG_INFO_DER_DESERIALIZER,
    //
    //  Deserializer of algorithm information from buffer to public key in DER
    //
    (vscf_alg_info_der_deserializer_api_from_der_data_fn)vscf_alg_info_der_deserialize_from_der_data
};

//
//  Compile-time known information about 'alg info der deserialize' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_alg_info_der_deserialize_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_alg_info_der_deserialize_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_alg_info_der_deserialize_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_init(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);

    vscf_zeroize(alg_info_der_deserialize_impl, sizeof(vscf_alg_info_der_deserialize_impl_t));

    alg_info_der_deserialize_impl->info = &info;
    alg_info_der_deserialize_impl->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_deserialize_init()'.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_cleanup(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    if (alg_info_der_deserialize_impl == NULL || alg_info_der_deserialize_impl->info == NULL) {
        return;
    }

    if (alg_info_der_deserialize_impl->refcnt == 0) {
        return;
    }

    if (--alg_info_der_deserialize_impl->refcnt > 0) {
        return;
    }

    vscf_alg_info_der_deserialize_release_asn1_reader(alg_info_der_deserialize_impl);
    vscf_alg_info_der_deserialize_release_alg_info(alg_info_der_deserialize_impl);

    vscf_zeroize(alg_info_der_deserialize_impl, sizeof(vscf_alg_info_der_deserialize_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_alg_info_der_deserialize_impl_t *
vscf_alg_info_der_deserialize_new(void) {

    vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl = (vscf_alg_info_der_deserialize_impl_t *) vscf_alloc(sizeof (vscf_alg_info_der_deserialize_impl_t));
    VSCF_ASSERT_ALLOC(alg_info_der_deserialize_impl);

    vscf_alg_info_der_deserialize_init(alg_info_der_deserialize_impl);

    return alg_info_der_deserialize_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_deserialize_new()'.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_delete(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    vscf_alg_info_der_deserialize_cleanup(alg_info_der_deserialize_impl);

    if (alg_info_der_deserialize_impl && (alg_info_der_deserialize_impl->refcnt == 0)) {
        vscf_dealloc(alg_info_der_deserialize_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_deserialize_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_destroy(vscf_alg_info_der_deserialize_impl_t **alg_info_der_deserialize_impl_ref) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl_ref);

    vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl = *alg_info_der_deserialize_impl_ref;
    *alg_info_der_deserialize_impl_ref = NULL;

    vscf_alg_info_der_deserialize_delete(alg_info_der_deserialize_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_alg_info_der_deserialize_impl_t *
vscf_alg_info_der_deserialize_copy(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    // Proxy to the parent implementation.
    return (vscf_alg_info_der_deserialize_impl_t *)vscf_impl_copy((vscf_impl_t *)alg_info_der_deserialize_impl);
}

//
//  Return size of 'vscf_alg_info_der_deserialize_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_alg_info_der_deserialize_impl_size(void) {

    return sizeof (vscf_alg_info_der_deserialize_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserialize_impl(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    return (vscf_impl_t *)(alg_info_der_deserialize_impl);
}

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_use_asn1_reader(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl,
        vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    alg_info_der_deserialize_impl->asn1_reader = vscf_impl_copy(asn1_reader);
}

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_take_asn1_reader(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl,
        vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    alg_info_der_deserialize_impl->asn1_reader = asn1_reader;
}

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_release_asn1_reader(
        vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);

    vscf_impl_destroy(&alg_info_der_deserialize_impl->asn1_reader);
}

//
//  Setup dependency to the interface 'alg info' with shared ownership.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_use_alg_info(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl,
        vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl->alg_info == NULL);

    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));

    alg_info_der_deserialize_impl->alg_info = vscf_impl_copy(alg_info);
}

//
//  Setup dependency to the interface 'alg info' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_take_alg_info(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl,
        vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl->alg_info == NULL);

    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));

    alg_info_der_deserialize_impl->alg_info = alg_info;
}

//
//  Release dependency to the interface 'alg info'.
//
VSCF_PUBLIC void
vscf_alg_info_der_deserialize_release_alg_info(vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);

    vscf_impl_destroy(&alg_info_der_deserialize_impl->alg_info);
}

static const vscf_api_t *
vscf_alg_info_der_deserialize_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG_INFO_DER_DESERIALIZER:
            return (const vscf_api_t *) &alg_info_der_deserializer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
