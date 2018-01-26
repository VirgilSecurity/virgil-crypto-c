//  Copyright (c) 2015-2018 Virgil Security Inc.
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

#ifndef VSF_IMPL_H_INCLUDED
#define VSF_IMPL_H_INCLUDED

#include "vsf_library.h"
#include "vsf_api.h"

#ifdef __cplusplus
extern "C" {
#endif

// Unique tag that defines specific algorithm implementation.
typedef enum _vsf_impl_tag_t {
    vsf_impl_tag_BEGIN = 0,
    vsf_impl_tag_HASH_SHA256,
    vsf_impl_tag_HASH_SHA512,
    vsf_impl_tag_END
} vsf_impl_tag_t;

//  Cleanup the object in a secure manner.
VSF_PUBLIC void
vsf_cleanup (void *impl);

//  Cleanup the object and deallocate it according to the de-allocation policy.
VSF_PUBLIC void
vsf_destroy (void **impl_ref);

//  Return requested API for given implementation.
VSF_PUBLIC const void *
vsf_api (void *impl, vsf_api_tag_t api_tag);

#ifdef __cplusplus
}
#endif

#endif // VSF_IMPL_H_INCLUDED
