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

#include "vsf_hmac512_internal.h"
#include "vsf_memory.h"
#include "vsf_assert.h"
#include "vsf_hmac512.h"
#include "vsf_hmac512_impl.h"
#include "vsf_hmac_info_api.h"
#include "vsf_hmac_api.h"
#include "vsf_hmac_stream_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'hmac info api'.
//
static const vsf_hmac_info_api_t hmac_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac_info' MUST be equal to the 'vsf_api_tag_HMAC_INFO'.
    //
    vsf_api_tag_HMAC_INFO,
    //
    //  Size of the digest (hmac output).
    //
    vsf_hmac512_DIGEST_SIZE
};

//
//  Configuration of the interface API 'hmac api'.
//
static const vsf_hmac_api_t hmac_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac' MUST be equal to the 'vsf_api_tag_HMAC'.
    //
    vsf_api_tag_HMAC,
    //
    //  Link to the inherited interface API 'hmac info'.
    //
    &hmac_info_api,
    //
    //  Calculate hmac over given data.
    //
    (vsf_hmac_api_hmac_fn) vsf_hmac512_hmac
};

//
//  Configuration of the interface API 'hmac stream api'.
//
static const vsf_hmac_stream_api_t hmac_stream_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac_stream' MUST be equal to the 'vsf_api_tag_HMAC_STREAM'.
    //
    vsf_api_tag_HMAC_STREAM,
    //
    //  Link to the inherited interface API 'hmac info'.
    //
    &hmac_info_api,
    //
    //  Reset HMAC.
    //
    (vsf_hmac_stream_api_reset_fn) vsf_hmac512_reset,
    //
    //  Start a new HMAC.
    //
    (vsf_hmac_stream_api_start_fn) vsf_hmac512_start,
    //
    //  Add given data to the HMAC.
    //
    (vsf_hmac_stream_api_update_fn) vsf_hmac512_update,
    //
    //  Accompilsh HMAC and return it's result (a message digest).
    //
    (vsf_hmac_stream_api_finish_fn) vsf_hmac512_finish
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vsf_api_t* api_array[] = {
    (const vsf_api_t*) &hmac_info_api,
    (const vsf_api_t*) &hmac_api,
    (const vsf_api_t*) &hmac_stream_api,
    NULL
};

//
//  Compile-time known information about 'hmac512' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_HMAC512,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_hmac512_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_delete_fn) vsf_hmac512_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_hmac512_init (vsf_hmac512_impl_t* hmac512_impl) {

    VSF_ASSERT_PTR (hmac512_impl);
    VSF_ASSERT_PTR (hmac512_impl->info == NULL);

    hmac512_impl->info = &info;

    return vsf_hmac512_init_ctx (hmac512_impl);
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac512_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hmac512_cleanup (vsf_hmac512_impl_t* hmac512_impl) {

    VSF_ASSERT_PTR (hmac512_impl);

    if (hmac512_impl->info == NULL) {
        return;
    }

    vsf_hmac512_cleanup_ctx (hmac512_impl);

    hmac512_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_hmac512_impl_t*
vsf_hmac512_new (void) {

    vsf_hmac512_impl_t *hmac512_impl = (vsf_hmac512_impl_t *) vsf_alloc (sizeof (vsf_hmac512_impl_t));
    VSF_ASSERT_PTR (hmac512_impl);

    vsf_hmac512_init (hmac512_impl);

    return hmac512_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac512_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_hmac512_delete (vsf_hmac512_impl_t* hmac512_impl) {

    if (hmac512_impl) {
        vsf_hmac512_cleanup (hmac512_impl);
        vsf_dealloc (hmac512_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_hmac512_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_hmac512_destroy (vsf_hmac512_impl_t** hmac512_impl_ref) {

    VSF_ASSERT_PTR (hmac512_impl_ref);

    vsf_hmac512_impl_t *hmac512_impl = *hmac512_impl_ref;
    *hmac512_impl_ref = NULL;

    vsf_hmac512_delete (hmac512_impl);
}

//
//  Returns instance of the implemented interface 'hmac info'.
//
VSF_PUBLIC const vsf_hmac_info_api_t*
vsf_hmac512_hmac_info_api (void) {

    return &hmac_info_api;
}

//
//  Returns instance of the implemented interface 'hmac'.
//
VSF_PUBLIC const vsf_hmac_api_t*
vsf_hmac512_hmac_api (void) {

    return &hmac_api;
}

//
//  Return size of 'vsf_hmac512_impl_t' type.
//
VSF_PUBLIC size_t
vsf_hmac512_impl_size (void) {

    return sizeof (vsf_hmac512_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_hmac512_impl (vsf_hmac512_impl_t* hmac512_impl) {

    VSF_ASSERT_PTR (hmac512_impl);
    return (vsf_impl_t *) (hmac512_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
