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
//  This module contains 'fake random' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_fake_random.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_fake_random_defs.h"
#include "vscf_fake_random_internal.h"

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
//  Note, this method is called automatically when method vscf_fake_random_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_fake_random_init_ctx(vscf_fake_random_t *fake_random) {

    VSCF_ASSERT_PTR(fake_random);

    fake_random->data_source.bytes = NULL;
    fake_random->data_source.len = 0;
    fake_random->byte_source = 0;
    fake_random->pos = 0;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_fake_random_cleanup_ctx(vscf_fake_random_t *fake_random) {

    VSCF_ASSERT_PTR(fake_random);

    (void)vscf_fake_random_init_ctx(fake_random);
}

//
//  Configure random number generator to generate sequence filled with given byte.
//
VSCF_PUBLIC void
vscf_fake_random_setup_source_byte(vscf_fake_random_t *fake_random, byte byte_source) {

    VSCF_ASSERT_PTR(fake_random);

    vscf_fake_random_init_ctx(fake_random);

    fake_random->byte_source = byte_source;
}

//
//  Configure random number generator to generate random sequence from given data.
//  Note, that given data is used as circular source.
//
VSCF_PUBLIC void
vscf_fake_random_setup_source_data(vscf_fake_random_t *fake_random, vsc_data_t data_source) {

    VSCF_ASSERT_PTR(fake_random);

    vscf_fake_random_init_ctx(fake_random);

    fake_random->data_source = data_source;
}

//
//  Generate random bytes.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_random(vscf_fake_random_t *fake_random, size_t data_len, vsc_buffer_t *data) {

    VSCF_ASSERT_PTR(fake_random);
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT(vsc_buffer_is_valid(data));

    VSCF_ASSERT(vsc_buffer_unused_len(data) >= data_len);

    const byte *end = vsc_buffer_unused_bytes(data) + data_len;

    for (byte *write_ptr = vsc_buffer_unused_bytes(data); write_ptr < end; ++write_ptr) {
        if (fake_random->data_source.bytes != NULL) {
            *write_ptr = *(fake_random->data_source.bytes + fake_random->pos);

            if (++fake_random->pos >= fake_random->data_source.len) {
                fake_random->pos = 0;
            }
        } else {
            *write_ptr = fake_random->byte_source;
        }
    }

    vsc_buffer_inc_used(data, data_len);

    return vscf_SUCCESS;
}

//
//  Retreive new seed data from the entropy sources.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_reseed(vscf_fake_random_t *fake_random) {

    VSCF_UNUSED(fake_random);

    return vscf_SUCCESS;
}

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_fake_random_is_strong(vscf_fake_random_t *fake_random) {

    VSCF_UNUSED(fake_random);

    return true;
}

//
//  Gather entropy of the requested length.
//
VSCF_PUBLIC vscf_error_t
vscf_fake_random_gather(vscf_fake_random_t *fake_random, size_t len, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(fake_random);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT(vsc_buffer_unused_len(out) >= len);

    return vscf_fake_random_random(fake_random, len, out);
}
