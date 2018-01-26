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

#include "vsf_memory.h"

#include "vsf_assert.h"

static void *
default_alloc (size_t size) {
    return VSF_ALLOC_DEFAULT (size);
}

static void
default_dealloc (void *mem) {
    return VSF_DEALLOC_DEFAULT (mem);
}

static vsf_alloc_fn inner_alloc = default_alloc;
static vsf_dealloc_fn inner_dealloc = default_dealloc;


VSF_PUBLIC void *
vsf_alloc (size_t size) {
    return inner_alloc (size);
}

VSF_PUBLIC void
vsf_dealloc (void *mem) {
    inner_dealloc (mem);
}

VSF_PUBLIC void
vsf_set_allocators (vsf_alloc_fn alloc_fn, vsf_dealloc_fn dealloc_fn) {
    VSF_ASSERT (alloc_fn);
    VSF_ASSERT (dealloc_fn);
    inner_alloc = alloc_fn;
    inner_dealloc = dealloc_fn;
}

VSF_PUBLIC void
vsf_zeroize (void *mem, size_t mem_size) {
    memset (mem, 0, mem_size);
}

VSF_PUBLIC void
vsf_zeroize_s (void *mem, size_t mem_size) {
    memset (mem, 0, mem_size);
}
