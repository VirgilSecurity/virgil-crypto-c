//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provides configurable memory management model.
// --------------------------------------------------------------------------

#ifndef CODEGEN_MEMORY_H_INCLUDED
#define CODEGEN_MEMORY_H_INCLUDED

#include "codegen_library.h"

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
CODEGEN_PUBLIC void *
codegen_alloc(size_t size);

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
CODEGEN_PUBLIC void *
codegen_calloc(size_t count, size_t size);

//
//  Deallocate given memory by usging current de-allocation function.
//
CODEGEN_PUBLIC void
codegen_dealloc(void *mem);

//
//  Change current used memory functions in the runtime.
//
CODEGEN_PUBLIC void
codegen_set_allocators(codegen_alloc_fn alloc_cb, codegen_dealloc_fn dealloc_cb);

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use codegen_erase().
//
CODEGEN_PUBLIC void
codegen_zeroize(void *mem, size_t size);

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
CODEGEN_PUBLIC void
codegen_erase(void *mem, size_t size);

//
//  Perform constant-time memory comparison.
//  The time depends on the given length but not on the compared memory.
//  Return true of given memory chunks are equal.
//
CODEGEN_PUBLIC bool
codegen_memory_secure_equal(const void *a, const void *b, size_t len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // CODEGEN_MEMORY_H_INCLUDED
//  @end
