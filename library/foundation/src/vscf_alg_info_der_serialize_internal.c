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

#include "vscf_alg_info_der_serialize_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_alg_info_der_serialize_impl.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_alg_info_der_serializer_api.h"
#include "vscf_asn1_writer.h"
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
vscf_alg_info_der_serialize_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg info der serializer api'.
//
static const vscf_alg_info_der_serializer_api_t alg_info_der_serializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg_info_der_serializer' MUST be equal to the 'vscf_api_tag_ALG_INFO_DER_SERIALIZER'.
    //
    vscf_api_tag_ALG_INFO_DER_SERIALIZER,
    //
    //  Serializer of algorithm information from public key in DER to buffer
    //
    (vscf_alg_info_der_serializer_api_to_der_data_fn)vscf_alg_info_der_serialize_to_der_data
};

//
//  Compile-time known information about 'alg info der serialize' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_alg_info_der_serialize_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_alg_info_der_serialize_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_alg_info_der_serialize_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_init(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);

    vscf_zeroize(alg_info_der_serialize_impl, sizeof(vscf_alg_info_der_serialize_impl_t));

    alg_info_der_serialize_impl->info = &info;
    alg_info_der_serialize_impl->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_serialize_init()'.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_cleanup(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    if (alg_info_der_serialize_impl == NULL || alg_info_der_serialize_impl->info == NULL) {
        return;
    }

    if (alg_info_der_serialize_impl->refcnt == 0) {
        return;
    }

    if (--alg_info_der_serialize_impl->refcnt > 0) {
        return;
    }

    vscf_alg_info_der_serialize_release_asn1_writer(alg_info_der_serialize_impl);
    vscf_alg_info_der_serialize_release_alg_info(alg_info_der_serialize_impl);

    vscf_zeroize(alg_info_der_serialize_impl, sizeof(vscf_alg_info_der_serialize_impl_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_alg_info_der_serialize_impl_t *
vscf_alg_info_der_serialize_new(void) {

    vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl = (vscf_alg_info_der_serialize_impl_t *) vscf_alloc(sizeof (vscf_alg_info_der_serialize_impl_t));
    VSCF_ASSERT_ALLOC(alg_info_der_serialize_impl);

    vscf_alg_info_der_serialize_init(alg_info_der_serialize_impl);

    return alg_info_der_serialize_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_serialize_new()'.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_delete(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    vscf_alg_info_der_serialize_cleanup(alg_info_der_serialize_impl);

    if (alg_info_der_serialize_impl && (alg_info_der_serialize_impl->refcnt == 0)) {
        vscf_dealloc(alg_info_der_serialize_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_alg_info_der_serialize_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_destroy(vscf_alg_info_der_serialize_impl_t **alg_info_der_serialize_impl_ref) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl_ref);

    vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl = *alg_info_der_serialize_impl_ref;
    *alg_info_der_serialize_impl_ref = NULL;

    vscf_alg_info_der_serialize_delete(alg_info_der_serialize_impl);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_alg_info_der_serialize_impl_t *
vscf_alg_info_der_serialize_copy(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    // Proxy to the parent implementation.
    return (vscf_alg_info_der_serialize_impl_t *)vscf_impl_copy((vscf_impl_t *)alg_info_der_serialize_impl);
}

//
//  Return size of 'vscf_alg_info_der_serialize_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_alg_info_der_serialize_impl_size(void) {

    return sizeof (vscf_alg_info_der_serialize_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_serialize_impl(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    return (vscf_impl_t *)(alg_info_der_serialize_impl);
}

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_use_asn1_writer(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl,
        vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT_PTR(alg_info_der_serialize_impl->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    alg_info_der_serialize_impl->asn1_writer = vscf_impl_copy(asn1_writer);
}

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_take_asn1_writer(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl,
        vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT_PTR(alg_info_der_serialize_impl->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    alg_info_der_serialize_impl->asn1_writer = asn1_writer;
}

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_release_asn1_writer(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);

    vscf_impl_destroy(&alg_info_der_serialize_impl->asn1_writer);
}

//
//  Setup dependency to the interface 'alg info' with shared ownership.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_use_alg_info(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl,
        vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(alg_info_der_serialize_impl->alg_info == NULL);

    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));

    alg_info_der_serialize_impl->alg_info = vscf_impl_copy(alg_info);
}

//
//  Setup dependency to the interface 'alg info' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_take_alg_info(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl,
        vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(alg_info_der_serialize_impl->alg_info == NULL);

    VSCF_ASSERT(vscf_alg_info_is_implemented(alg_info));

    alg_info_der_serialize_impl->alg_info = alg_info;
}

//
//  Release dependency to the interface 'alg info'.
//
VSCF_PUBLIC void
vscf_alg_info_der_serialize_release_alg_info(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);

    vscf_impl_destroy(&alg_info_der_serialize_impl->alg_info);
}

static const vscf_api_t *
vscf_alg_info_der_serialize_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG_INFO_DER_SERIALIZER:
            return (const vscf_api_t *) &alg_info_der_serializer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
