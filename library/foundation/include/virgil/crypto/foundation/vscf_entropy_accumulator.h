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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains 'entropy accumulator' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_ENTROPY_ACCUMULATOR_H_INCLUDED
#define VSCF_ENTROPY_ACCUMULATOR_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Public integral constants.
//
enum {
    vscf_entropy_accumulator_SOURCES_MAX = 15
};

//
//  Handles implementation details.
//
typedef struct vscf_entropy_accumulator_t vscf_entropy_accumulator_t;

//
//  Return size of 'vscf_entropy_accumulator_t' type.
//
VSCF_PUBLIC size_t
vscf_entropy_accumulator_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_entropy_accumulator_impl(vscf_entropy_accumulator_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_entropy_accumulator_impl_const(const vscf_entropy_accumulator_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_init(vscf_entropy_accumulator_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_entropy_accumulator_init()'.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_cleanup(vscf_entropy_accumulator_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_entropy_accumulator_t *
vscf_entropy_accumulator_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_entropy_accumulator_new()'.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_delete(vscf_entropy_accumulator_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_entropy_accumulator_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_destroy(vscf_entropy_accumulator_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_entropy_accumulator_t *
vscf_entropy_accumulator_shallow_copy(vscf_entropy_accumulator_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_setup_defaults(vscf_entropy_accumulator_t *self);

//
//  Add given entropy source to the accumulator.
//  Threshold defines minimum number of bytes that must be gathered
//  from the source during accumulation.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_add_source(vscf_entropy_accumulator_t *self, vscf_impl_t *source, size_t threshold);

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_entropy_accumulator_is_strong(vscf_entropy_accumulator_t *self);

//
//  Gather entropy of the requested length.
//
VSCF_PUBLIC vscf_status_t
vscf_entropy_accumulator_gather(vscf_entropy_accumulator_t *self, size_t len, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ENTROPY_ACCUMULATOR_H_INCLUDED
//  @end
