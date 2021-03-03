//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "vscf_memory.h"
#include "vscf_assert.h"

#include <stdio.h>
#include <stdarg.h>

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
#   define VSCF_ALLOC_DEFAULT(size) VIRGIL_PLATFORM_ALLOC((size))
#else
#   define VSCF_ALLOC_DEFAULT(size) calloc(1, (size))
#endif

//
//  Compile-time configuration of the default dealloc function.
//
#ifdef VIRGIL_PLATFORM_DEALLOC
#   define VSCF_DEALLOC_DEFAULT(mem) VIRGIL_PLATFORM_DEALLOC(mem)
#else
#   define VSCF_DEALLOC_DEFAULT(mem) free((mem))
#endif

//
//  Default allocation function, that is configured during compilation.
//
static void *
vscf_default_alloc(size_t size);

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vscf_default_dealloc(void *mem);

//
//  Current allocation function.
//
static vscf_alloc_fn inner_alloc = vscf_default_alloc;

//
//  Current de-allocation function.
//
static vscf_dealloc_fn inner_dealloc = vscf_default_dealloc;

//
//  Default allocation function, that is configured during compilation.
//
static void *
vscf_default_alloc(size_t size) {

    return VSCF_ALLOC_DEFAULT(size);
}

//
//  Default de-allocation function, that is configured during compilation.
//
static void
vscf_default_dealloc(void *mem) {

    VSCF_DEALLOC_DEFAULT(mem);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSCF_PUBLIC void *
vscf_alloc(size_t size) {

    return inner_alloc(size);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSCF_PUBLIC void *
vscf_calloc(size_t count, size_t size) {

    return inner_alloc(count * size);
}

//
//  Deallocate given memory by usging current de-allocation function.
//
VSCF_PUBLIC void
vscf_dealloc(void *mem) {

    inner_dealloc(mem);
}

//
//  Change current used memory functions in the runtime.
//
VSCF_PUBLIC void
vscf_set_allocators(vscf_alloc_fn alloc_cb, vscf_dealloc_fn dealloc_cb) {

    VSCF_ASSERT_PTR(alloc_cb);
    VSCF_ASSERT_PTR(dealloc_cb);

    inner_alloc = alloc_cb;
    inner_dealloc = dealloc_cb;
}

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use vscf_erase().
//
VSCF_PUBLIC void
vscf_zeroize(void *mem, size_t size) {

    VSCF_ASSERT_PTR(mem);
    memset(mem, 0, size);
}

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
VSCF_PUBLIC void
vscf_erase(void *mem, size_t size) {

    VSCF_ASSERT_PTR(mem);

    volatile uint8_t* p = (uint8_t*)mem;
    while (size--) { *p++ = 0; }
}

//
//  Perform constant-time memory comparison.
//  The time depends on the given length but not on the compared memory.
//  Return true of given memory chunks are equal.
//
VSCF_PUBLIC bool
vscf_memory_secure_equal(const void *a, const void *b, size_t len) {

    VSCF_ASSERT_PTR(a);
    VSCF_ASSERT_PTR(b);

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
VSCF_PUBLIC char *
vscf_strnstr(const char *s, const char *find, size_t slen) {

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

//
//  Fixed version of the snprintf().
//
VSCF_PUBLIC int
vscf_snprintf(char *s, size_t n, const char *format, ...) {

    va_list args;
    int ret;
    va_start(args, format);

    #if defined(__MINGW32__)
        ret = __mingw_vsnprintf(s, n, format, args);
    #else
        ret = vsnprintf(s, n, format, args);
    #endif

    va_end(args);
    return ret;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
