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

#include "vscf_hkdf_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_hkdf.h"
#include "vscf_hkdf_impl.h"
#include "vscf_ex_kdf_api.h"
#include "vscf_hmac_stream.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'ex_kdf api'.
//
static const vscf_ex_kdf_api_t ex_kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'ex_kdf' MUST be equal to the 'vscf_api_tag_EX_KDF'.
    //
    vscf_api_tag_EX_KDF,
    //
    //  Calculate hash over given data.
    //
    (vscf_ex_kdf_api_derive_fn)vscf_hkdf_derive
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vscf_api_t *api_array[] = {
    (const vscf_api_t *)&ex_kdf_api,
    NULL
};

//
//  Compile-time known information about 'hkdf' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_HKDF,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vscf_impl_cleanup_fn)vscf_hkdf_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_hkdf_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC vscf_error_t
vscf_hkdf_init(vscf_hkdf_impl_t *hkdf_impl) {

    VSCF_ASSERT_PTR (hkdf_impl);
    VSCF_ASSERT_PTR (hkdf_impl->info == NULL);

    hkdf_impl->info = &info;

    return vscf_SUCCESS;
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hkdf_cleanup(vscf_hkdf_impl_t *hkdf_impl) {

    VSCF_ASSERT_PTR (hkdf_impl);

    if (hkdf_impl->info == NULL) {
        return;
    }

    //   Cleanup dependency: 'hmac'.
    if (hkdf_impl->hmac) {

        if (hkdf_impl->is_owning_hmac) {
            vscf_impl_destroy (&hkdf_impl->hmac);

        } else {
            vscf_impl_cleanup (hkdf_impl->hmac);
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
VSCF_PUBLIC vscf_hkdf_impl_t *
vscf_hkdf_new(void) {

    vscf_hkdf_impl_t *hkdf_impl = (vscf_hkdf_impl_t *) vscf_alloc (sizeof (vscf_hkdf_impl_t));
    if (NULL == hkdf_impl) {
        return NULL;
    }

    if (vscf_hkdf_init (hkdf_impl) != vscf_SUCCESS) {
        vscf_dealloc(hkdf_impl);
        return NULL;
    }

    return hkdf_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hkdf_delete(vscf_hkdf_impl_t *hkdf_impl) {

    if (hkdf_impl) {
        vscf_hkdf_cleanup (hkdf_impl);
        vscf_dealloc (hkdf_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hkdf_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hkdf_destroy(vscf_hkdf_impl_t * *hkdf_impl_ref) {

    VSCF_ASSERT_PTR (hkdf_impl_ref);

    vscf_hkdf_impl_t *hkdf_impl = *hkdf_impl_ref;
    *hkdf_impl_ref = NULL;

    vscf_hkdf_delete (hkdf_impl);
}

//
//  Setup dependency to the interface 'hmac stream' and keep ownership.
//
VSCF_PUBLIC void
vscf_hkdf_use_hmac_stream(vscf_hkdf_impl_t *hkdf_impl, vscf_impl_t *hmac) {

    VSCF_ASSERT_PTR (hkdf_impl);
    VSCF_ASSERT_PTR (hmac);
    VSCF_ASSERT_PTR (hkdf_impl->hmac == NULL);

    VSCF_ASSERT (vscf_hmac_stream_is_implemented (hmac));

    hkdf_impl->hmac = hmac;

    hkdf_impl->is_owning_hmac = 0;
}

//
//  Setup dependency to the interface 'hmac stream' and transfer ownership.
//
VSCF_PUBLIC void
vscf_hkdf_take_hmac_stream(vscf_hkdf_impl_t *hkdf_impl, vscf_impl_t * *hmac_ref) {

    VSCF_ASSERT_PTR (hkdf_impl);
    VSCF_ASSERT_PTR (hmac_ref);
    VSCF_ASSERT_PTR (hkdf_impl->hmac == NULL);

    vscf_impl_t *hmac = *hmac_ref;
    *hmac_ref = NULL;
    VSCF_ASSERT_PTR (hmac);

    VSCF_ASSERT (vscf_hmac_stream_is_implemented (hmac));

    hkdf_impl->hmac = hmac;

    hkdf_impl->is_owning_hmac = 1;
}

//
//  Return size of 'vscf_hkdf_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_hkdf_impl_size(void) {

    return sizeof (vscf_hkdf_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hkdf_impl(vscf_hkdf_impl_t *hkdf_impl) {

    VSCF_ASSERT_PTR (hkdf_impl);
    return (vscf_impl_t *) (hkdf_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
