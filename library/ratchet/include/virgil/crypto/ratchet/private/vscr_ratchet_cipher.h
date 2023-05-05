//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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

#ifndef VSCR_RATCHET_CIPHER_H_INCLUDED
#define VSCR_RATCHET_CIPHER_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_typedefs.h"
#include "vscr_ratchet_message_key.h"
#include "vscr_status.h"

#include <vscr_RatchetMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <virgil/crypto/foundation/private/vscf_message_padding.h>

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
//  Handle 'ratchet cipher' context.
//
typedef struct vscr_ratchet_cipher_t vscr_ratchet_cipher_t;

//
//  Return size of 'vscr_ratchet_cipher_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_init(vscr_ratchet_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_cleanup(vscr_ratchet_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_delete(vscr_ratchet_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_cipher_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_destroy(vscr_ratchet_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_shallow_copy(vscr_ratchet_cipher_t *self);

VSCR_PUBLIC size_t
vscr_ratchet_cipher_encrypt_len(vscr_ratchet_cipher_t *self, size_t plain_text_len);

VSCR_PUBLIC size_t
vscr_ratchet_cipher_decrypt_len(vscr_ratchet_cipher_t *self, size_t cipher_text_len);

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_encrypt(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key, vsc_data_t plain_text,
        vsc_data_t additional_data, vsc_buffer_t *buffer) VSCR_NODISCARD;

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key, vsc_data_t cipher_text,
        vsc_data_t additional_data, vsc_buffer_t *buffer) VSCR_NODISCARD;

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_pad_then_encrypt(vscr_ratchet_cipher_t *self, vscf_message_padding_t *padding, vsc_data_t data,
        const vscr_ratchet_message_key_t *key, vsc_data_t ad, vsc_buffer_t *cipher_text) VSCR_NODISCARD;

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt_then_remove_pad(vscr_ratchet_cipher_t *self, vsc_data_t data,
        const vscr_ratchet_message_key_t *key, vsc_data_t ad, vsc_buffer_t *plain_text) VSCR_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_CIPHER_H_INCLUDED
//  @end
