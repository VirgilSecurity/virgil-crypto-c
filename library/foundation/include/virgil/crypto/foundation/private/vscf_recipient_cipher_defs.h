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
//  Class 'recipient cipher' types definition.
// --------------------------------------------------------------------------

#ifndef VSCF_RECIPIENT_CIPHER_DEFS_H_INCLUDED
#define VSCF_RECIPIENT_CIPHER_DEFS_H_INCLUDED

#include "vscf_library.h"
#include "vscf_atomic.h"
#include "vscf_key_recipient_list.h"
#include "vscf_signer_list.h"
#include "vscf_message_info.h"
#include "vscf_message_info_footer.h"
#include "vscf_impl.h"
#include "vscf_message_info_der_serializer.h"
#include "vscf_recipient_cipher_decryption_state.h"

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
//  Handle 'recipient cipher' context.
//
struct vscf_recipient_cipher_t {
    //
    //  Function do deallocate self context.
    //
    vscf_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    VSCF_ATOMIC size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *random;
    //
    //  Dependency to the interface 'cipher'.
    //
    vscf_impl_t *encryption_cipher;
    //
    //  Dependency to the interface 'hash'.
    //
    vscf_impl_t *signer_hash;

    vscf_key_recipient_list_t *key_recipients;

    vscf_signer_list_t *signers;

    vsc_buffer_t *cipher_key_material;

    vsc_buffer_t *data_digest;

    vsc_buffer_t *decryption_recipient_id;

    vscf_impl_t *decryption_recipient_key;

    vsc_buffer_t *decryption_password;

    vscf_impl_t *decryption_cipher;

    vscf_message_info_t *message_info;

    vscf_message_info_der_serializer_t *message_info_der_serializer;

    vsc_buffer_t *message_info_buffer;

    vscf_message_info_footer_t *message_info_footer;

    vsc_buffer_t *message_info_footer_enc;

    size_t message_info_expected_len;

    vscf_recipient_cipher_decryption_state_t decryption_state;

    bool is_signed_operation;
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
#endif // VSCF_RECIPIENT_CIPHER_DEFS_H_INCLUDED
//  @end
