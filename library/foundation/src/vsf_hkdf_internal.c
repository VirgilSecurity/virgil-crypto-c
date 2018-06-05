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

#include "vsf_hkdf_internal.h"
#include "vsf_memory.h"
#include "vsf_assert.h"
#include "vsf_hkdf.h"
#include "vsf_hkdf_impl.h"
#include "vsf_ex_kdf_api.h"
#include "vsf_hmac_stream.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'ex_kdf api'.
//
static const vsf_ex_kdf_api_t ex_kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'ex_kdf' MUST be equal to the 'vsf_api_tag_EX_KDF'.
    //
    vsf_api_tag_EX_KDF,
    //
    //  Calculate hash over given data.
    //
    (vsf_ex_kdf_api_derive_fn) vsf_hkdf_derive
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vsf_api_t* api_array[] = {
    (const vsf_api_t*) &ex_kdf_api,
    NULL
};

//
//  Compile-time known information about 'hkdf' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_HKDF,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_hkdf_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_delete_fn) vsf_hkdf_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_hkdf_init(vsf_hkdf_impl_t* hkdf_impl) {

    VSF_ASSERT_PTR (hkdf_impl);
    VSF_ASSERT_PTR (hkdf_impl->info == NULL);

    hkdf_impl->info = &info;

    return vsf_SUCCESS;
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hkdf_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hkdf_cleanup(vsf_hkdf_impl_t* hkdf_impl) {

    VSF_ASSERT_PTR (hkdf_impl);

    if (hkdf_impl->info == NULL) {
        return;
    }

    //   Cleanup dependency: 'hmac'.
    if (hkdf_impl->hmac) {

        if (hkdf_impl->is_owning_hmac) {
            vsf_impl_destroy (&hkdf_impl->hmac);

        } else {
            vsf_impl_cleanup (hkdf_impl->hmac);
            hkdf_impl->hmac = NULL;
        }

        hkdf_impl->is_owning_hmac = 0;
    }

    hkdf_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_hkdf_impl_t*
vsf_hkdf_new(void) {

    vsf_hkdf_impl_t *hkdf_impl = (vsf_hkdf_impl_t *) vsf_alloc (sizeof (vsf_hkdf_impl_t));
    VSF_ASSERT_PTR (hkdf_impl);

    vsf_hkdf_init (hkdf_impl);

    return hkdf_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hkdf_delete(vsf_hkdf_impl_t* hkdf_impl) {

    if (hkdf_impl) {
        vsf_hkdf_cleanup (hkdf_impl);
        vsf_dealloc (hkdf_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_hkdf_destroy(vsf_hkdf_impl_t** hkdf_impl_ref) {

    VSF_ASSERT_PTR (hkdf_impl_ref);

    vsf_hkdf_impl_t *hkdf_impl = *hkdf_impl_ref;
    *hkdf_impl_ref = NULL;

    vsf_hkdf_delete (hkdf_impl);
}

//
//  Setup dependency to the interface 'hmac stream' and keep ownership.
//
VSF_PUBLIC void
vsf_hkdf_use_hmac_stream(vsf_hkdf_impl_t* hkdf_impl, vsf_impl_t* hmac) {

    VSF_ASSERT_PTR (hkdf_impl);
    VSF_ASSERT_PTR (hmac);
    VSF_ASSERT_PTR (hkdf_impl->hmac == NULL);

    VSF_ASSERT (vsf_hmac_stream_is_implemented (hmac));

    hkdf_impl->hmac = hmac;

    hkdf_impl->is_owning_hmac = 0;
}

//
//  Setup dependency to the interface 'hmac stream' and transfer ownership.
//
VSF_PUBLIC void
vsf_hkdf_take_hmac_stream(vsf_hkdf_impl_t* hkdf_impl, vsf_impl_t** hmac_ref) {

    VSF_ASSERT_PTR (hkdf_impl);
    VSF_ASSERT_PTR (hmac_ref);
    VSF_ASSERT_PTR (hkdf_impl->hmac == NULL);

    vsf_impl_t *hmac = *hmac_ref;
    *hmac_ref = NULL;
    VSF_ASSERT_PTR (hmac);

    VSF_ASSERT (vsf_hmac_stream_is_implemented (hmac));

    hkdf_impl->hmac = hmac;

    hkdf_impl->is_owning_hmac = 1;
}

//
//  Return size of 'vsf_hkdf_impl_t' type.
//
VSF_PUBLIC size_t
vsf_hkdf_impl_size(void) {

    return sizeof (vsf_hkdf_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_hkdf_impl(vsf_hkdf_impl_t* hkdf_impl) {

    VSF_ASSERT_PTR (hkdf_impl);
    return (vsf_impl_t *) (hkdf_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
