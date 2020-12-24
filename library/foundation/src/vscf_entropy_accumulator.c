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
//  This module contains 'entropy accumulator' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_entropy_accumulator.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_entropy_accumulator_defs.h"
#include "vscf_entropy_accumulator_internal.h"
#include "vscf_entropy_source.h"
#include "vscf_mbedtls_bridge_entropy_poll.h"

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
//  Note, this method is called automatically when method vscf_entropy_accumulator_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_entropy_accumulator_init_ctx(vscf_entropy_accumulator_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_entropy_init(&self->ctx);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_entropy_accumulator_cleanup_ctx(vscf_entropy_accumulator_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_entropy_free(&self->ctx);

    while (self->source_count > 0) {
        vscf_impl_destroy(&self->sources[--self->source_count]);
    }
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_setup_defaults(vscf_entropy_accumulator_t *self) {

    VSCF_ASSERT_PTR(self);
    bool has_strong = 0;

#if defined(MBEDTLS_PLATFORM_ENTROPY)
    mbedtls_entropy_add_source(&self->ctx, mbedtls_platform_entropy_poll, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM,
            MBEDTLS_ENTROPY_SOURCE_STRONG);
    has_strong = true;
#endif

#if defined(MBEDTLS_TIMING_C)
    mbedtls_entropy_add_source(
            &self->ctx, mbedtls_hardclock_poll, NULL, MBEDTLS_ENTROPY_MIN_HARDCLOCK, MBEDTLS_ENTROPY_SOURCE_WEAK);
#endif

#if defined(MBEDTLS_HAVEGE_C)
    mbedtls_entropy_add_source(&self->ctx, mbedtls_havege_poll, &self->ctx.havege_data, MBEDTLS_ENTROPY_MIN_HAVEGE,
            MBEDTLS_ENTROPY_SOURCE_STRONG);
    has_strong = true;
#endif

    VSCF_ASSERT(has_strong);
}

//
//  Add given entropy source to the accumulator.
//  Threshold defines minimum number of bytes that must be gathered
//  from the source during accumulation.
//
VSCF_PUBLIC void
vscf_entropy_accumulator_add_source(vscf_entropy_accumulator_t *self, vscf_impl_t *source, size_t threshold) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(source);
    VSCF_ASSERT(vscf_entropy_source_is_implemented(source));
    VSCF_ASSERT(threshold > 0);
    VSCF_ASSERT(self->source_count < vscf_entropy_accumulator_SOURCES_MAX);

    self->sources[self->source_count++] = vscf_impl_shallow_copy(source);

    int status = mbedtls_entropy_add_source(
            &self->ctx, vscf_mbedtls_bridge_entropy_poll, source, threshold, vscf_entropy_source_is_strong(source));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_entropy_accumulator_is_strong(vscf_entropy_accumulator_t *self) {

    VSCF_ASSERT_PTR(self);

    return true;
}

//
//  Gather entropy of the requested length.
//
VSCF_PUBLIC vscf_status_t
vscf_entropy_accumulator_gather(vscf_entropy_accumulator_t *self, size_t len, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(len > 0);
    VSCF_ASSERT(len <= MBEDTLS_ENTROPY_BLOCK_SIZE);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= len);

    int status = mbedtls_entropy_func(&self->ctx, vsc_buffer_unused_bytes(out), len);

    switch (status) {
    case 0:
        vsc_buffer_inc_used(out, len);
        return vscf_status_SUCCESS;

    case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
        return vscf_status_ERROR_ENTROPY_SOURCE_FAILED;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(status);
        return vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR;
    }
}
