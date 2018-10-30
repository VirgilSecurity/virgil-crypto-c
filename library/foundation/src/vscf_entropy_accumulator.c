//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
#include "vscf_entropy_accumulator_impl.h"
#include "vscf_entropy_accumulator_internal.h"

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
vscf_entropy_accumulator_init_ctx(vscf_entropy_accumulator_impl_t *entropy_accumulator_impl) {

    VSCF_ASSERT_PTR(entropy_accumulator_impl);

    mbedtls_entropy_init(&entropy_accumulator_impl->ctx);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_entropy_accumulator_cleanup_ctx(vscf_entropy_accumulator_impl_t *entropy_accumulator_impl) {

    VSCF_ASSERT_PTR(entropy_accumulator_impl);

    mbedtls_entropy_free(&entropy_accumulator_impl->ctx);
}

//
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_entropy_accumulator_is_strong(vscf_entropy_accumulator_impl_t *entropy_accumulator_impl) {

    VSCF_ASSERT_PTR(entropy_accumulator_impl);

    return true;
}

//
//  Provide gathered entropy of the requested length.
//
VSCF_PUBLIC vscf_error_t
vscf_entropy_accumulator_provide(
        vscf_entropy_accumulator_impl_t *entropy_accumulator_impl, size_t len, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(entropy_accumulator_impl);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(len > 0);
    VSCF_ASSERT(len <= MBEDTLS_ENTROPY_BLOCK_SIZE);
    VSCF_ASSERT(vsc_buffer_left(out) >= 0);

    int result = mbedtls_entropy_func(&entropy_accumulator_impl->ctx, vsc_buffer_ptr(out), len);

    switch (result) {
    case 0:
        vsc_buffer_reserve(out, len);
        return vscf_SUCCESS;

    case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
        return vscf_error_ENTROPY_SOURCE_FAILED;

    default:
        return vscf_error_UNHANDLED_THIRDPARTY_ERROR;
    }
}
