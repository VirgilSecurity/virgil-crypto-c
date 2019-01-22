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
//  This module contains 'cipher alg info' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_cipher_alg_info.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_cipher_alg_info_defs.h"
#include "vscf_cipher_alg_info_internal.h"

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
//  Note, this method is called automatically when method vscf_cipher_alg_info_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_cipher_alg_info_init_ctx(vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_cipher_alg_info_cleanup_ctx(vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);
    vsc_buffer_destroy(&cipher_alg_info->nonce);
}

//
//  Create symmetric cipher algorithm info with identificator and input vector.
//
VSCF_PUBLIC vscf_cipher_alg_info_t *
vscf_cipher_alg_info_new_with_members(vscf_alg_id_t alg_id, vsc_data_t nonce) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(nonce));
    VSCF_ASSERT(nonce.len > 0);

    vscf_cipher_alg_info_t *cipher_alg_info = vscf_cipher_alg_info_new();

    cipher_alg_info->alg_id = alg_id;
    cipher_alg_info->nonce = vsc_buffer_new_with_data(nonce);

    return cipher_alg_info;
}

//
//  Return IV.
//
VSCF_PUBLIC vsc_data_t
vscf_cipher_alg_info_nonce(const vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);
    VSCF_ASSERT_PTR(cipher_alg_info->nonce);

    return vsc_buffer_data(cipher_alg_info->nonce);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_cipher_alg_info_alg_id(const vscf_cipher_alg_info_t *cipher_alg_info) {

    VSCF_ASSERT_PTR(cipher_alg_info);

    return cipher_alg_info->alg_id;
}
