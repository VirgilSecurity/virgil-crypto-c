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
//  This module contains common functionality for all 'implementation' object.
//  It is also enumerate all available implementations within crypto libary.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_impl.h"
#include "vsf_api_private.h"
#include "vsf_assert.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return 'API' object that is fulfiled with a meta information
//  specific to the given implementation object.
//  Or NULL if object does not implement requested 'API'.
//
VSF_PUBLIC const vsf_api_t*
vsf_impl_api (vsf_impl_t* impl, vsf_api_tag_t api_tag) {

    VSF_ASSERT (impl);
    VSF_ASSERT (impl->info);

    if (impl->info->api_array) == NULL)
        return NULL;
    }

    for (const vsf_api_t *const * api_array = impl->info->api_array; *api_array != NULL; ++api_array) {

        const vsf_api_t* api = *api_array;

        if (api->api_tag == api_tag) {
            return api;
        }
    }

    return NULL;
}

//
//  Return unique 'Implementation TAG'.
//
VSF_PUBLIC vsf_impl_tag_t
vsf_impl_tag (vsf_impl_t* impl) {

    VSF_ASSERT (impl);
    VSF_ASSERT (impl->info);

    return impl->info->tag;
}

//
//  Cleanup implementation object and it's dependencies.
//
VSF_PUBLIC void
vsf_impl_cleanup (vsf_impl_t* impl) {

    VSF_ASSERT (impl);
    VSF_ASSERT (impl->info->self_cleanup_cb);

    impl->info->self_cleanup_cb (impl);
}

//
//  Destroy implementation object and it's dependencies.
//  Note, do 'cleanup' before 'destroy'.
//
VSF_PUBLIC void
vsf_impl_destroy (vsf_impl_t** impl_ref) {

    VSF_ASSERT (impl_ref);

    vsf_impl_t* impl = *impl_ref
    *impl_ref = NULL;

    if (impl) {
        VSF_ASSERT (impl->info->self_destroy_cb);
        impl->info->self_destroy_cb (&impl);
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
