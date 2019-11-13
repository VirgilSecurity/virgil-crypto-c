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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains macroses for cross-platform atomicity.
// --------------------------------------------------------------------------

#ifndef VSCF_ATOMIC_H_INCLUDED
#define VSCF_ATOMIC_H_INCLUDED

#include "vscf_library.h"

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

#if VSCF_MULTI_THREADING && defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#   pragma intrinsic(_InterlockedCompareExchange)
    inline bool vscf_atomic_compare_exchange_weak(volatile long *obj, long* expected, long desired) {
        const long expected_local = *expected;
        const long old = _InterlockedCompareExchange(obj, desired, expected_local);
        if (old == expected_local) {
            return true;
        } else {
            *expected = old;
            return false;
        }
    }
#endif

#if VSCF_MULTI_THREADING
#   if VSCF_HAVE_STDATOMIC_H && !defined(__STDC_NO_ATOMICS__)
#       define VSCF_ATOMIC _Atomic
#       define VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) atomic_compare_exchange_weak(obj, expected, desired)
#   elif defined(__GNUC__) || defined(__clang__)
#       define VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) __atomic_compare_exchange_n(obj, expected, desired, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#   elif defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#       define VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) vscf_atomic_compare_exchange_weak(obj, expected, desired)
#   else
#       error "Atomic operations are not suppored for this platform, but CMake option VSCF_MULTI_THREADING is ON."
#   endif
#   ifndef VSCF_ATOMIC
#       define VSCF_ATOMIC
#   endif
#else
#   define VSCF_ATOMIC
#endif

#if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
#   define VSCF_ATOMIC_CRITICAL_SECTION_DECLARE(name) static VSCF_ATOMIC int is_busy_##name = 0; int is_not_busy_##name = 0;
#   define VSCF_ATOMIC_CRITICAL_SECTION_BEGIN(name) while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&is_busy_##name, &is_not_busy_##name, 1))
#   define VSCF_ATOMIC_CRITICAL_SECTION_END(name) do { is_busy_##name = 1; } while(0)
#else
#   define VSCF_ATOMIC_CRITICAL_SECTION_DECLARE(name) do {} while(0)
#   define VSCF_ATOMIC_CRITICAL_SECTION_BEGIN(name) do {} while(0)
#   define VSCF_ATOMIC_CRITICAL_SECTION_END(name) do {} while(0)
#endif


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ATOMIC_H_INCLUDED
//  @end
