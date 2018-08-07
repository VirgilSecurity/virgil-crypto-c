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

#include "vscf_hmac256_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_hmac256.h"
#include "vscf_hmac256_impl.h"
#include "vscf_hmac_info_api.h"
#include "vscf_hmac_api.h"
#include "vscf_hmac_stream_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'hmac info api'.
//
static const vscf_hmac_info_api_t hmac_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac_info' MUST be equal to the 'vscf_api_tag_HMAC_INFO'.
    //
    vscf_api_tag_HMAC_INFO,
    //
    //  Size of the digest (hmac output).
    //
    vscf_hmac256_DIGEST_SIZE
};

//
//  Configuration of the interface API 'hmac api'.
//
static const vscf_hmac_api_t hmac_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac' MUST be equal to the 'vscf_api_tag_HMAC'.
    //
    vscf_api_tag_HMAC,
    //
    //  Link to the inherited interface API 'hmac info'.
    //
    &hmac_info_api,
    //
    //  Calculate hmac over given data.
    //
    (vscf_hmac_api_hmac_fn)vscf_hmac256_hmac
};

//
//  Configuration of the interface API 'hmac stream api'.
//
static const vscf_hmac_stream_api_t hmac_stream_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac_stream' MUST be equal to the 'vscf_api_tag_HMAC_STREAM'.
    //
    vscf_api_tag_HMAC_STREAM,
    //
    //  Link to the inherited interface API 'hmac info'.
    //
    &hmac_info_api,
    //
    //  Reset HMAC.
    //
    (vscf_hmac_stream_api_reset_fn)vscf_hmac256_reset,
    //
    //  Start a new HMAC.
    //
    (vscf_hmac_stream_api_start_fn)vscf_hmac256_start,
    //
    //  Add given data to the HMAC.
    //
    (vscf_hmac_stream_api_update_fn)vscf_hmac256_update,
    //
    //  Accompilsh HMAC and return it's result (a message digest).
    //
    (vscf_hmac_stream_api_finish_fn)vscf_hmac256_finish
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vscf_api_t *api_array[] = {
    (const vscf_api_t *)&hmac_info_api,
    (const vscf_api_t *)&hmac_api,
    (const vscf_api_t *)&hmac_stream_api,
    NULL
};

//
//  Compile-time known information about 'hmac256' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_HMAC256,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vscf_impl_cleanup_fn)vscf_hmac256_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_hmac256_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC vscf_error_t
vscf_hmac256_init(vscf_hmac256_impl_t *hmac256_impl) {

    VSCF_ASSERT_PTR (hmac256_impl);
    VSCF_ASSERT_PTR (hmac256_impl->info == NULL);

    hmac256_impl->info = &info;

    return vscf_hmac256_init_ctx (hmac256_impl);
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac256_init ()'.
//  All dependencies that is under ownership will be destroyed.
//  All dependencies that is not under ownership will untouched.
//
VSCF_PUBLIC void
vscf_hmac256_cleanup(vscf_hmac256_impl_t *hmac256_impl) {

    VSCF_ASSERT_PTR (hmac256_impl);

    if (hmac256_impl->info == NULL) {
        return;
    }

    vscf_hmac256_cleanup_ctx (hmac256_impl);

    hmac256_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hmac256_impl_t *
vscf_hmac256_new(void) {

    vscf_hmac256_impl_t *hmac256_impl = (vscf_hmac256_impl_t *) vscf_alloc (sizeof (vscf_hmac256_impl_t));
    if (NULL == hmac256_impl) {
        return NULL;
    }

    if (vscf_hmac256_init (hmac256_impl) != vscf_SUCCESS) {
        vscf_dealloc(hmac256_impl);
        return NULL;
    }

    return hmac256_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac256_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_hmac256_delete(vscf_hmac256_impl_t *hmac256_impl) {

    if (hmac256_impl) {
        vscf_hmac256_cleanup (hmac256_impl);
        vscf_dealloc (hmac256_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hmac256_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hmac256_destroy(vscf_hmac256_impl_t **hmac256_impl_ref) {

    VSCF_ASSERT_PTR (hmac256_impl_ref);

    vscf_hmac256_impl_t *hmac256_impl = *hmac256_impl_ref;
    *hmac256_impl_ref = NULL;

    vscf_hmac256_delete (hmac256_impl);
}

//
//  Returns instance of the implemented interface 'hmac info'.
//
VSCF_PUBLIC const vscf_hmac_info_api_t *
vscf_hmac256_hmac_info_api(void) {

    return &hmac_info_api;
}

//
//  Returns instance of the implemented interface 'hmac'.
//
VSCF_PUBLIC const vscf_hmac_api_t *
vscf_hmac256_hmac_api(void) {

    return &hmac_api;
}

//
//  Return size of 'vscf_hmac256_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_hmac256_impl_size(void) {

    return sizeof (vscf_hmac256_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hmac256_impl(vscf_hmac256_impl_t *hmac256_impl) {

    VSCF_ASSERT_PTR (hmac256_impl);
    return (vscf_impl_t *) (hmac256_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
