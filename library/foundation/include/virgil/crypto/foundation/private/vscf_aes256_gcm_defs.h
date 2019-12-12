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
//  Types of the 'aes256 gcm' implementation.
//  This types SHOULD NOT be used directly.
//  The only purpose of including this module is to place implementation
//  object in the stack memory.
// --------------------------------------------------------------------------

#ifndef VSCF_AES256_GCM_DEFS_H_INCLUDED
#define VSCF_AES256_GCM_DEFS_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl_private.h"
#include "vscf_aes256_gcm.h"
#include "vscf_atomic.h"
#include "vscf_cipher_state.h"

#include <mbedtls/cipher.h>

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
//  Handles implementation details.
//
struct vscf_aes256_gcm_t {
    //
    //  Compile-time known information about this implementation.
    //
    const vscf_impl_info_t *info;
    //
    //  Reference counter.
    //
    VSCF_ATOMIC size_t refcnt;
    //
    //  Implementation specific context.
    //
    mbedtls_cipher_context_t cipher_ctx;
    //
    //  Implementation specific context.
    //
    byte key[vscf_aes256_gcm_KEY_LEN];
    //
    //  Implementation specific context.
    //
    byte nonce[vscf_aes256_gcm_NONCE_LEN];
    //
    //  Implementation specific context.
    //
    vsc_buffer_t *auth_data;
    //
    //  Implementation specific context.
    //
    vscf_cipher_state_t state;
    //
    //  Implementation specific context.
    //
    byte cached_data[vscf_aes256_gcm_BLOCK_LEN];
    //
    //  Implementation specific context.
    //
    byte auth_tag[vscf_aes256_gcm_AUTH_TAG_LEN];
    //
    //  Implementation specific context.
    //
    size_t cached_data_len;
    //
    //  Implementation specific context.
    //
    size_t auth_tag_len;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_AES256_GCM_DEFS_H_INCLUDED
//  @end
