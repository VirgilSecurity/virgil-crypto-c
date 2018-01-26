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


#ifndef VSF_BUFFER_API_H_INCLUDED
#define VSF_BUFFER_API_H_INCLUDED

#include "vsf_buffer.h"
#include "vsf_api.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct _vsf_buffer_t {
    vsf_dealloc_fn dealloc_fn;
    byte* data;
    size_t size;
    size_t used_size;
} vsf_buffer_t;

struct _vsf_buffer_api_t {
    //  API unique identifier, MUST be first in the structure.
    //  For algorithms that support buffer MUST be set to the "vsf_api_tag_BUFFER".
    vsf_api_tag_t api_tag;

    //  Return object buffer.
    //  Scope: PRIVATE.
    vsf_buffer_t * (*buffer) (void *impl);

    //  Calculate required buffer size.
    size_t (*calc_size) (void *impl);
};

typedef vsf_buffer_t * (*vsf_buffer_api_buffer_fn) (void *impl);
typedef size_t (*vsf_buffer_api_calc_size_fn) (void *impl);


//  Return mixin state object.
VSF_PRIVATE vsf_buffer_t *
vsf_buffer_variable(void* impl);

#ifdef __cplusplus
}
#endif

#endif // VSF_BUFFER_API_H_INCLUDED
