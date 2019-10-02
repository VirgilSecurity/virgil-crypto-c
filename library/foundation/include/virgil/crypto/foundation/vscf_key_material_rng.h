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
//  This module contains 'key material rng' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_MATERIAL_RNG_H_INCLUDED
#define VSCF_KEY_MATERIAL_RNG_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

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
//  Public integral constants.
//
enum {
    //
    //  Minimum length in bytes for the key material.
    //
    vscf_key_material_rng_KEY_MATERIAL_LEN_MIN = 32,
    //
    //  Maximum length in bytes for the key material.
    //
    vscf_key_material_rng_KEY_MATERIAL_LEN_MAX = 512
};

//
//  Handles implementation details.
//
typedef struct vscf_key_material_rng_t vscf_key_material_rng_t;

//
//  Return size of 'vscf_key_material_rng_t' type.
//
VSCF_PUBLIC size_t
vscf_key_material_rng_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_material_rng_impl(vscf_key_material_rng_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_key_material_rng_impl_const(const vscf_key_material_rng_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_key_material_rng_init(vscf_key_material_rng_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_key_material_rng_init()'.
//
VSCF_PUBLIC void
vscf_key_material_rng_cleanup(vscf_key_material_rng_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_key_material_rng_t *
vscf_key_material_rng_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_key_material_rng_new()'.
//
VSCF_PUBLIC void
vscf_key_material_rng_delete(vscf_key_material_rng_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_key_material_rng_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_key_material_rng_destroy(vscf_key_material_rng_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_material_rng_t *
vscf_key_material_rng_shallow_copy(vscf_key_material_rng_t *self);

//
//  Set a new key material.
//
VSCF_PUBLIC void
vscf_key_material_rng_reset_key_material(vscf_key_material_rng_t *self, vsc_data_t key_material);

//
//  Generate random bytes.
//  All RNG implementations must be thread-safe.
//
VSCF_PUBLIC vscf_status_t
vscf_key_material_rng_random(const vscf_key_material_rng_t *self, size_t data_len, vsc_buffer_t *data) VSCF_NODISCARD;

//
//  Retrieve new seed data from the entropy sources.
//
VSCF_PUBLIC vscf_status_t
vscf_key_material_rng_reseed(vscf_key_material_rng_t *self) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_MATERIAL_RNG_H_INCLUDED
//  @end
