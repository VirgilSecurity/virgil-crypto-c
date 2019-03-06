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

#ifndef VSCR_RATCHET_CIPHER_H_INCLUDED
#define VSCR_RATCHET_CIPHER_H_INCLUDED

#include "vscr_library.h"
#include "vscr_status.h"

#include <virgil/crypto/foundation/vscf_aes256_gcm.h>

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_aes256_gcm.h>
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
//  Public integral constants.
//
enum {
    vscr_ratchet_cipher_KEY_LEN = 32
};

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
//  It is safe to call this method even if context was allocated by the caller.
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

//
//  Setup dependency to the implementation 'aes256 gcm' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_use_aes256_gcm(vscr_ratchet_cipher_t *self, vscf_aes256_gcm_t *aes256_gcm);

//
//  Setup dependency to the implementation 'aes256 gcm' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_take_aes256_gcm(vscr_ratchet_cipher_t *self, vscf_aes256_gcm_t *aes256_gcm);

//
//  Release dependency to the implementation 'aes256 gcm'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_release_aes256_gcm(vscr_ratchet_cipher_t *self);

VSCR_PUBLIC size_t
vscr_ratchet_cipher_encrypt_len(vscr_ratchet_cipher_t *self, size_t plain_text_len);

VSCR_PUBLIC size_t
vscr_ratchet_cipher_decrypt_len(vscr_ratchet_cipher_t *self, size_t cipher_text_len);

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_encrypt(vscr_ratchet_cipher_t *self, vsc_data_t key, vsc_data_t plain_text, vsc_buffer_t *buffer);

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt(vscr_ratchet_cipher_t *self, vsc_data_t key, vsc_data_t cipher_text, vsc_buffer_t *buffer);


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
