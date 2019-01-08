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


#include "vsf_api_info.h"
#include "vsf_impl_info.h"
#include "vsf_assert.h"


//  Cleanup the object in a secure manner.
VSF_PUBLIC void
vsf_cleanup (void *impl) {
    VSF_ASSERT (impl);

    vsf_impl_header_t *impl_header = (vsf_impl_header_t *)impl;
    VSF_ASSERT (impl_header);
    VSF_ASSERT (impl_header->info);

    VSF_ASSERT (impl_header->info->self_cleanup);
    impl_header->info->self_cleanup (impl);
}


//  Cleanup the object and deallocate it according to the de-allocation policy.
VSF_PUBLIC void
vsf_destroy (void **impl_ref) {
    VSF_ASSERT (impl_ref);

    vsf_impl_header_t *impl_header = (vsf_impl_header_t *)(*impl_ref);
    VSF_ASSERT (impl_header);
    VSF_ASSERT (impl_header->info);

    VSF_ASSERT (impl_header->info->self_destroy);
    impl_header->info->self_destroy (impl_ref);
}

//  Return requested API for given implementation.
VSF_PUBLIC const void *
vsf_api (void *impl, vsf_api_tag_t api_tag) {
    VSF_ASSERT (impl);
    VSF_ASSERT (vsf_api_tag_BEGIN < api_tag);
    VSF_ASSERT (vsf_api_tag_END > api_tag);

    vsf_impl_header_t *impl_header = (vsf_impl_header_t *)impl;
    VSF_ASSERT (impl_header);
    VSF_ASSERT (impl_header->info);

    if (impl_header->info->api_list == NULL) {
        return NULL;
    }

    for (const void * const *api = impl_header->info->api_list; *api != NULL; ++api) {
        const api_header_t *api_header = (const api_header_t *)(*api);
        if (api_header->api_tag == api_tag) {
            return *api;
        }
    }

    return NULL;
}
