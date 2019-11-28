//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


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

#include "vsce_memory.h"
#include "vsce_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Include external platform header if defined.
//
#ifdef VIRGIL_PLATFORM_INCLUDE_STATEMENT
#   include VIRGIL_PLATFORM_INCLUDE_STATEMENT
#endif

//
//  Compile-time configuration of the default alloc function.
//
#ifdef VIRGIL_PLATFORM_ALLOC
#   define VSCE_ALLOC_DEFAULT(size) VIRGIL_PLATFORM_ALLOC((size))
#else
#   define VSCE_ALLOC_DEFAULT(size) calloc(1, (size))
#endif

//
//  Compile-time configuration of the default dealloc function.
//
#ifdef VIRGIL_PLATFORM_DEALLOC
#   define VSCE_DEALLOC_DEFAULT(mem) VIRGIL_PLATFORM_DEALLOC(mem)
#else
#   define VSCE_DEALLOC_DEFAULT(mem) free((mem))
#endif

//
//  Default allocation function, that is configured during compilation.
//
static void *
vsce_default_alloc(size_t size);

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vsce_default_dealloc(void *mem);

//
//  Current allocation function.
//
static vsce_alloc_fn inner_alloc = vsce_default_alloc;

//
//  Current de-allocation function.
//
static vsce_dealloc_fn inner_dealloc = vsce_default_dealloc;

//
//  Default allocation function, that is configured during compilation.
//
static void *
vsce_default_alloc(size_t size) {

    return VSCE_ALLOC_DEFAULT(size);
}

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vsce_default_dealloc(void *mem) {

    VSCE_DEALLOC_DEFAULT(mem);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSCE_PUBLIC void *
vsce_alloc(size_t size) {

    return inner_alloc(size);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSCE_PUBLIC void *
vsce_calloc(size_t count, size_t size) {

    return inner_alloc(count * size);
}

//
//  Deallocate given memory by usging current de-allocation function.
//
VSCE_PUBLIC void
vsce_dealloc(void *mem) {

    inner_dealloc(mem);
}

//
//  Change current used memory functions in the runtime.
//
VSCE_PUBLIC void
vsce_set_allocators(vsce_alloc_fn alloc_cb, vsce_dealloc_fn dealloc_cb) {

    VSCE_ASSERT_PTR(alloc_cb);
    VSCE_ASSERT_PTR(dealloc_cb);

    inner_alloc = alloc_cb;
    inner_dealloc = dealloc_cb;
}

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use vsce_erase().
//
VSCE_PUBLIC void
vsce_zeroize(void *mem, size_t size) {

    VSCE_ASSERT_PTR(mem);
    memset(mem, 0, size);
}

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
VSCE_PUBLIC void
vsce_erase(void *mem, size_t size) {

    VSCE_ASSERT_PTR(mem);

    volatile uint8_t* p = (uint8_t*)mem;
    while (size--) { *p++ = 0; }
}

//
//  Perform constant-time memory comparison.
//  The time depends on the given length but not on the compared memory.
//  Return true of given memory chunks are equal.
//
VSCE_PUBLIC bool
vsce_memory_secure_equal(const void *a, const void *b, size_t len) {

    VSCE_ASSERT_PTR(a);
    VSCE_ASSERT_PTR(b);

    const volatile uint8_t *in_a = a;
    const volatile uint8_t *in_b = b;
    volatile uint8_t c = 0x00;

    for (size_t i = 0; i < len; ++i) {
        c |= in_a[i] ^ in_b[i];
    }

    return c == 0;
}

//
//  Find the first occurrence of find in s, where the search is limited to the
//  first slen characters of s.
//
VSCE_PUBLIC char *
vsce_strnstr(const char *s, const char *find, size_t slen) {

    /*-
     * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
     * Copyright (c) 1990, 1993
     * The Regents of the University of California. All rights reserved.
     *
     * This code is derived from software contributed to Berkeley by
     * Chris Torek.
     *
     * Redistribution and use in source and binary forms, with or without
     * modification, are permitted provided that the following conditions
     * are met:
     * 1. Redistributions of source code must retain the above copyright
     * notice, this list of conditions and the following disclaimer.
     * 2. Redistributions in binary form must reproduce the above copyright
     * notice, this list of conditions and the following disclaimer in the
     * documentation and/or other materials provided with the distribution.
     * 3. All advertising materials mentioning features or use of this software
     * must display the following acknowledgement:
     * This product includes software developed by the University of
     * California, Berkeley and its contributors.
     * 4. Neither the name of the University nor the names of its contributors
     * may be used to endorse or promote products derived from this software
     * without specific prior written permission.
     *
     * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
     * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
     * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
     * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
     * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
     * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
     * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
     * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
     * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
     * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
     * SUCH DAMAGE.
     */

    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0') // Fixed by Virgil Security, Inc.
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
