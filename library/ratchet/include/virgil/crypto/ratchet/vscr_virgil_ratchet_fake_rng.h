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
//  This module contains 'virgil ratchet fake rng' implementation.
// --------------------------------------------------------------------------

#ifndef VSCR_VIRGIL_RATCHET_FAKE_RNG_H_INCLUDED
#define VSCR_VIRGIL_RATCHET_FAKE_RNG_H_INCLUDED

#include "vscr_library.h"
#include "vscr_impl.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#endif

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
//  Handles implementation details.
//
typedef struct vscr_virgil_ratchet_fake_rng_t vscr_virgil_ratchet_fake_rng_t;

//
//  Return size of 'vscr_virgil_ratchet_fake_rng_t' type.
//
VSCR_PUBLIC size_t
vscr_virgil_ratchet_fake_rng_impl_size(void);

//
//  Cast to the 'vscr_impl_t' type.
//
VSCR_PUBLIC vscr_impl_t *
vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng);

//
//  Perform initialization of preallocated implementation context.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_init(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_init()'.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_cleanup(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCR_PUBLIC vscr_virgil_ratchet_fake_rng_t *
vscr_virgil_ratchet_fake_rng_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_new()'.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_delete(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscr_virgil_ratchet_fake_rng_new()'.
//  Given reference is nullified.
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_destroy(vscr_virgil_ratchet_fake_rng_t **virgil_ratchet_fake_rng_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCR_PUBLIC vscr_virgil_ratchet_fake_rng_t *
vscr_virgil_ratchet_fake_rng_shallow_copy(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng);

//
//  Interface for ratchet rng
//
VSCR_PUBLIC void
vscr_virgil_ratchet_fake_rng_generate_random_data(vscr_virgil_ratchet_fake_rng_t *virgil_ratchet_fake_rng, size_t size,
        vsc_buffer_t *random);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_VIRGIL_RATCHET_FAKE_RNG_H_INCLUDED
//  @end
