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
//  This module contains 'key material rng' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_material_rng.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_ctr_drbg.h"
#include "vscf_seed_entropy_source.h"
#include "vscf_key_material_rng_defs.h"
#include "vscf_key_material_rng_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_key_material_rng_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_key_material_rng_init_ctx(vscf_key_material_rng_t *self) {

    VSCF_ASSERT_PTR(self);

    self->seed_entropy_source = vscf_seed_entropy_source_new();
    self->ctr_drbg = vscf_ctr_drbg_new();
    vscf_ctr_drbg_use_entropy_source(self->ctr_drbg, vscf_seed_entropy_source_impl(self->seed_entropy_source));
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_key_material_rng_cleanup_ctx(vscf_key_material_rng_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ctr_drbg_destroy(&self->ctr_drbg);
    vscf_seed_entropy_source_destroy(&self->seed_entropy_source);
}

//
//  Set a new key material.
//
VSCF_PUBLIC void
vscf_key_material_rng_reset_key_material(vscf_key_material_rng_t *self, vsc_data_t key_material) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ctr_drbg);
    VSCF_ASSERT_PTR(self->seed_entropy_source);
    VSCF_ASSERT(key_material.len >= vscf_key_material_rng_KEY_MATERIAL_LEN_MIN);
    VSCF_ASSERT(key_material.len <= vscf_key_material_rng_KEY_MATERIAL_LEN_MAX);

    vscf_seed_entropy_source_reset_seed(self->seed_entropy_source, key_material);
    vscf_ctr_drbg_release_entropy_source(self->ctr_drbg);
    vscf_ctr_drbg_use_entropy_source(self->ctr_drbg, vscf_seed_entropy_source_impl(self->seed_entropy_source));
}

//
//  Generate random bytes.
//
VSCF_PUBLIC vscf_status_t
vscf_key_material_rng_random(vscf_key_material_rng_t *self, size_t data_len, vsc_buffer_t *data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ctr_drbg);
    VSCF_ASSERT(data_len > 0);
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT(vsc_buffer_is_valid(data));
    VSCF_ASSERT(vsc_buffer_unused_len(data) >= data_len);

    return vscf_ctr_drbg_random(self->ctr_drbg, data_len, data);
}

//
//  Retreive new seed data from the entropy sources.
//
VSCF_PUBLIC vscf_status_t
vscf_key_material_rng_reseed(vscf_key_material_rng_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->ctr_drbg);

    return vscf_ctr_drbg_reseed(self->ctr_drbg);
}
