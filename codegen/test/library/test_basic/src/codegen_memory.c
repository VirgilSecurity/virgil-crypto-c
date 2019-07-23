//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
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

#include "codegen_memory.h"
#include "codegen_assert.h"

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
#   define CODEGEN_ALLOC_DEFAULT(size) VIRGIL_PLATFORM_ALLOC((size))
#else
#   define CODEGEN_ALLOC_DEFAULT(size) calloc(1, (size))
#endif

//
//  Compile-time configuration of the default dealloc function.
//
#ifdef VIRGIL_PLATFORM_DEALLOC
#   define CODEGEN_DEALLOC_DEFAULT(mem) VIRGIL_PLATFORM_DEALLOC(mem)
#else
#   define CODEGEN_DEALLOC_DEFAULT(mem) free((mem))
#endif

//
//  Default allocation function, that is configured during compilation.
//
static void *
codegen_default_alloc(size_t size);

//
//  Default de-allocation function, that is configured during compilation.
//
static void
codegen_default_dealloc(void *mem);

//
//  Current allocation function.
//
static codegen_alloc_fn inner_alloc = codegen_default_alloc;

//
//  Current de-allocation function.
//
static codegen_dealloc_fn inner_dealloc = codegen_default_dealloc;

//
//  Default allocation function, that is configured during compilation.
//
static void *
codegen_default_alloc(size_t size) {

    return CODEGEN_ALLOC_DEFAULT(size);
}

//
//  Default de-allocation function, that is configured during compilation.
//
static void
codegen_default_dealloc(void *mem) {

    CODEGEN_DEALLOC_DEFAULT(mem);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
CODEGEN_PUBLIC void *
codegen_alloc(size_t size) {

    return inner_alloc(size);
}

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
CODEGEN_PUBLIC void *
codegen_calloc(size_t count, size_t size) {

    return inner_alloc(count * size);
}

//
//  Deallocate given memory by usging current de-allocation function.
//
CODEGEN_PUBLIC void
codegen_dealloc(void *mem) {

    inner_dealloc(mem);
}

//
//  Change current used memory functions in the runtime.
//
CODEGEN_PUBLIC void
codegen_set_allocators(codegen_alloc_fn alloc_cb, codegen_dealloc_fn dealloc_cb) {

    CODEGEN_ASSERT_PTR(alloc_cb);
    CODEGEN_ASSERT_PTR(dealloc_cb);

    inner_alloc = alloc_cb;
    inner_dealloc = dealloc_cb;
}

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use codegen_erase().
//
CODEGEN_PUBLIC void
codegen_zeroize(void *mem, size_t size) {

    CODEGEN_ASSERT_PTR(mem);
    memset(mem, 0, size);
}

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
CODEGEN_PUBLIC void
codegen_erase(void *mem, size_t size) {

    CODEGEN_ASSERT_PTR(mem);

    volatile uint8_t* p = (uint8_t*)mem;
    while (size--) { *p++ = 0; }
}

//
//  Perform constant-time memory comparison.
//  The time depends on the given length but not on the compared memory.
//  Return true of given memory chunks are equal.
//
CODEGEN_PUBLIC bool
codegen_memory_secure_equal(const void *a, const void *b, size_t len) {

    CODEGEN_ASSERT_PTR(a);
    CODEGEN_ASSERT_PTR(b);

    const volatile uint8_t *in_a = a;
    const volatile uint8_t *in_b = b;
    volatile uint8_t c = 0x00;

    for (size_t i = 0; i < len; ++i) {
        c |= in_a[i] ^ in_b[i];
    }

    return c == 0;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
