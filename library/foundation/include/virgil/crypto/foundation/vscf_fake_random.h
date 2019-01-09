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
//  This module contains 'fake random' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_FAKE_RANDOM_H_INCLUDED
#define VSCF_FAKE_RANDOM_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_error.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
typedef struct vscf_fake_random_t vscf_fake_random_t;

//
//  Return size of 'vscf_fake_random_t' type.
//
VSCF_PUBLIC size_t
vscf_fake_random_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_fake_random_impl(vscf_fake_random_t *fake_random);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_fake_random_init(vscf_fake_random_t *fake_random);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_fake_random_init()'.
//
VSCF_PUBLIC void
vscf_fake_random_cleanup(vscf_fake_random_t *fake_random);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_fake_random_t *
vscf_fake_random_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_fake_random_new()'.
//
VSCF_PUBLIC void
vscf_fake_random_delete(vscf_fake_random_t *fake_random);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_fake_random_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_fake_random_destroy(vscf_fake_random_t **fake_random_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_fake_random_t *
vscf_fake_random_shallow_copy(vscf_fake_random_t *fake_random);

//
//  Configure random number generator to generate sequence filled with given byte.
//
VSCF_PUBLIC void
vscf_fake_random_setup_source_byte(vscf_fake_random_t *fake_random, byte byte_source);

//
//  Configure random number generator to generate random sequence from given data.
//  Note, that given data is used as circular source.
//
VSCF_PUBLIC void
vscf_fake_random_setup_source_data(vscf_fake_random_t *fake_random, vsc_data_t data_source);

//
//  Generate random bytes.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_random(vscf_fake_random_t *fake_random, size_t data_len, vsc_buffer_t *data);

//
//  Retreive new seed data from the entropy sources.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_reseed(vscf_fake_random_t *fake_random);

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_fake_random_is_strong(vscf_fake_random_t *fake_random);

//
//  Gather entropy of the requested length.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_gather(vscf_fake_random_t *fake_random, size_t len, vsc_buffer_t *out);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_FAKE_RANDOM_H_INCLUDED
//  @end
