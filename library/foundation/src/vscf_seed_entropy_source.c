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
//  This module contains 'seed entropy source' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_seed_entropy_source.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_kdf2.h"
#include "vscf_sha512.h"
#include "vscf_hash.h"
#include "vscf_kdf.h"
#include "vscf_seed_entropy_source_defs.h"
#include "vscf_seed_entropy_source_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    //
    //  The maximum length of the entropy requested at once.
    //
    vscf_seed_entropy_source_GATHER_LEN_MAX = 48
};

//
//  Current source is exhausted and must be refreshed.
//
static void
vscf_seed_entropy_source_move_forward(vscf_seed_entropy_source_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_seed_entropy_source_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_seed_entropy_source_init_ctx(vscf_seed_entropy_source_t *self) {

    VSCF_ASSERT_PTR(self);

    self->hash = vscf_sha512_impl(vscf_sha512_new());

    vscf_kdf2_t *kdf2 = vscf_kdf2_new();
    vscf_kdf2_use_hash(kdf2, self->hash);
    self->kdf = vscf_kdf2_impl(kdf2);

    self->entropy = vsc_buffer_new_with_capacity(vscf_seed_entropy_source_GATHER_LEN_MAX);
    vsc_buffer_inc_used(self->entropy, vscf_seed_entropy_source_GATHER_LEN_MAX);
    vsc_buffer_make_secure(self->entropy);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_seed_entropy_source_cleanup_ctx(vscf_seed_entropy_source_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->kdf);
    vscf_impl_destroy(&self->hash);
    vsc_buffer_destroy(&self->entropy);
}

//
//  Set a new seed as an entropy source.
//
VSCF_PUBLIC void
vscf_seed_entropy_source_reset_seed(vscf_seed_entropy_source_t *self, vsc_data_t seed) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->entropy);
    VSCF_ASSERT(vsc_data_is_valid(seed));

    vsc_buffer_erase(self->entropy);
    vscf_kdf_derive(self->kdf, seed, vscf_seed_entropy_source_GATHER_LEN_MAX, self->entropy);

    self->used_len = 0;
    self->counter = 0;
}

//
//  Current source is exhausted and must be refreshed.
//
static void
vscf_seed_entropy_source_move_forward(vscf_seed_entropy_source_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(self->entropy);

    ++self->counter;

    byte counter_string[4] = {0x0};
    counter_string[0] = (byte)((self->counter >> 24) & 255);
    counter_string[1] = (byte)((self->counter >> 16) & 255);
    counter_string[2] = (byte)((self->counter >> 8) & 255);
    counter_string[3] = (byte)(self->counter & 255);

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_hash_digest_len(vscf_hash_api(self->hash)));
    vsc_buffer_make_secure(digest);

    vscf_hash_start(self->hash);
    vscf_hash_update(self->hash, vsc_buffer_data(self->entropy));
    vscf_hash_update(self->hash, vsc_data(counter_string, sizeof(counter_string)));
    vscf_hash_finish(self->hash, digest);

    vscf_seed_entropy_source_reset_seed(self, vsc_buffer_data(digest));
    vsc_buffer_destroy(&digest);
}

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_seed_entropy_source_is_strong(vscf_seed_entropy_source_t *self) {

    VSCF_ASSERT_PTR(self);

    //  Strong if given seed is strong itself.
    return true;
}

//
//  Gather entropy of the requested length.
//
VSCF_PUBLIC vscf_status_t
vscf_seed_entropy_source_gather(vscf_seed_entropy_source_t *self, size_t len, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(self->entropy);
    VSCF_ASSERT(len > 0);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= len);

    size_t provided_len = 0;
    while (provided_len < len) {
        if (self->used_len == vsc_buffer_len(self->entropy)) {
            vscf_seed_entropy_source_move_forward(self);
        }
        VSCF_ASSERT(self->used_len < vsc_buffer_len(self->entropy));
        size_t can_provide_len = vsc_buffer_len(self->entropy) - self->used_len;
        size_t need_provide_len = (size_t)(len - provided_len);
        size_t do_provide_len = need_provide_len < can_provide_len ? need_provide_len : can_provide_len; // MIN

        vsc_data_t provided_entropy =
                vsc_data_slice_beg(vsc_buffer_data(self->entropy), self->used_len, do_provide_len);
        vsc_buffer_write_data(out, provided_entropy);

        provided_len += do_provide_len;
        self->used_len += do_provide_len;
    }

    return vscf_status_SUCCESS;
}
