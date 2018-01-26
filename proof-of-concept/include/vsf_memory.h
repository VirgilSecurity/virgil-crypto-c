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

#ifndef VSF_MEMORY_H_INCLUDED
#define VSF_MEMORY_H_INCLUDED

#include "vsf_library.h"


#ifdef __cplusplus
extern "C" {
#endif


#ifndef VSF_ALLOC_DEFAULT
#   define  VSF_ALLOC_DEFAULT(size) calloc (1, (size))
#endif

#ifndef VSF_DEALLOC_DEFAULT
#   define  VSF_DEALLOC_DEFAULT(mem) free ((mem))
#endif

VSF_PUBLIC void *
vsf_alloc (size_t size);

VSF_PUBLIC void
vsf_dealloc (void *mem);

VSF_PUBLIC void
vsf_set_allocators (vsf_alloc_fn alloc_fn, vsf_dealloc_fn dealloc_fn);

VSF_PUBLIC void
vsf_zeroize (void *mem, size_t mem_size);

VSF_PUBLIC void
vsf_zeroize_s (void *mem, size_t mem_size);



#ifdef __cplusplus
}
#endif

#endif // VSF_MEMORY_H_INCLUDED
