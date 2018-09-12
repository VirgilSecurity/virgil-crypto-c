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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'hmac224' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_hmac224.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_hmac224_impl.h"
#include "vscf_hmac224_internal.h"
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
//
VSCF_PRIVATE void
vscf_hmac224_init_ctx(vscf_hmac224_impl_t *hmac224_impl) {

    mbedtls_md_init(&hmac224_impl->hmac_ctx);
    int result = mbedtls_md_setup(&hmac224_impl->hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA224), 1);

    VSCF_ASSERT_ALLOC(result != MBEDTLS_ERR_MD_ALLOC_FAILED);
    VSCF_ASSERT(result == 0 && "unhandled mbedtls error");
}

//
//  Provides cleanup of the implementation specific context.
//
VSCF_PRIVATE void
vscf_hmac224_cleanup_ctx(vscf_hmac224_impl_t *hmac224_impl) {

    mbedtls_md_free(&hmac224_impl->hmac_ctx);
}

//
//  Calculate hmac over given data.
//
VSCF_PUBLIC void
vscf_hmac224_hmac(vsc_data_t key, vsc_data_t data, vsc_buffer_t *hmac) {

    VSCF_ASSERT_OPT(hmac_len >= vscf_hmac224_DIGEST_LEN);

    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA224), key, key_len, data, data_len, hmac);
}

//
//  Reset HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_reset(vscf_hmac224_impl_t *hmac224_impl) {

    mbedtls_md_hmac_reset(&hmac224_impl->hmac_ctx);
}

//
//  Start a new HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_start(vscf_hmac224_impl_t *hmac224_impl, vsc_data_t key) {

    mbedtls_md_hmac_starts(&hmac224_impl->hmac_ctx, key, key_len);
}

//
//  Add given data to the HMAC.
//
VSCF_PUBLIC void
vscf_hmac224_update(vscf_hmac224_impl_t *hmac224_impl, vsc_data_t data) {

    mbedtls_md_hmac_update(&hmac224_impl->hmac_ctx, data, data_len);
}

//
//  Accompilsh HMAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hmac224_finish(vscf_hmac224_impl_t *hmac224_impl, vsc_buffer_t *hmac) {

    VSCF_ASSERT_OPT(hmac_len >= vscf_hmac224_DIGEST_LEN);

    mbedtls_md_hmac_finish(&hmac224_impl->hmac_ctx, hmac);
}
