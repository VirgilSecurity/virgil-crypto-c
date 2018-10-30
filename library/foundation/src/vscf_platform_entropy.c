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
//  This module contains 'platform entropy' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_platform_entropy.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_platform_entropy_impl.h"
#include "vscf_platform_entropy_internal.h"

#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>

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
//  Defines that implemented source is strong.
//
VSCF_PUBLIC bool
vscf_platform_entropy_is_strong(vscf_platform_entropy_impl_t *platform_entropy_impl) {

    VSCF_ASSERT_PTR(platform_entropy_impl);
    return true;
}

//
//  Provide gathered entropy of the requested length.
//
VSCF_PUBLIC vscf_error_t
vscf_platform_entropy_provide(vscf_platform_entropy_impl_t *platform_entropy_impl, size_t len, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(platform_entropy_impl);
    VSCF_ASSERT(len > 0);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_left(out) >= len);

    size_t olen = 0;

    int result = mbedtls_platform_entropy_poll(NULL, vsc_buffer_ptr(out), len, &olen);

    switch (result) {
    case 0:
        vsc_buffer_reserve(out, olen);
        return vscf_SUCCESS;

    case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
        return vscf_error_ENTROPY_SOURCE_FAILED;

    default:
        return vscf_error_UNHANDLED_THIRDPARTY_ERROR;
    }
}
