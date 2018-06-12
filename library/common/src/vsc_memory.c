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
//  Provides configurable memory management model.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_memory.h"
#include "vsc_assert.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Default allocation function, that is configured during compilation.
//
static void *
vsc_default_alloc(size_t size);

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vsc_default_dealloc(void *mem);

//
//  Current allocation function.
//
static vsc_alloc_fn inner_alloc = vsc_default_alloc;

//
//  Current de-allocation function.
//
static vsc_dealloc_fn inner_dealloc = vsc_default_dealloc;

//
//  Default allocation function, that is configured during compilation.
//
static void *
vsc_default_alloc(size_t size) {

    return VSC_ALLOC_DEFAULT (size);
}

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vsc_default_dealloc(void *mem) {

    VSC_DEALLOC_DEFAULT (mem);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSC_PUBLIC void *
vsc_alloc(size_t size) {

    return inner_alloc (size);
}

//
//  Deallocate given memory by usging current de-allocation function.
//
VSC_PUBLIC void
vsc_dealloc(void *mem) {

    inner_dealloc (mem);
}

//
//  Change current used memory functions in the runtime.
//
VSC_PUBLIC void
vsc_set_allocators(vsc_alloc_fn alloc_cb, vsc_dealloc_fn dealloc_cb) {

    VSC_ASSERT_PTR (alloc_cb);
    VSC_ASSERT_PTR (dealloc_cb);

    inner_alloc = alloc_cb;
    inner_dealloc = dealloc_cb;
}

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use vsc_erase ().
//
VSC_PUBLIC void
vsc_zeroize(void *mem, size_t size) {

    VSC_ASSERT_PTR (mem);
    memset (mem, 0, size);
}

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
VSC_PUBLIC void
vsc_erase(void *mem, size_t size) {

    VSC_ASSERT_PTR (mem);

    volatile uint8_t* p = (uint8_t*)mem;
    while (size--) { *p++ = 0; }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
