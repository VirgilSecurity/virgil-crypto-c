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
//  Class for encryption using PHE account key
//  This class is thread-safe.
// --------------------------------------------------------------------------

#ifndef VSCE_PHE_CIPHER_H_INCLUDED
#define VSCE_PHE_CIPHER_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_status.h"

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
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
//  Handle 'phe cipher' context.
//
typedef struct vsce_phe_cipher_t vsce_phe_cipher_t;

//
//  Return size of 'vsce_phe_cipher_t'.
//
VSCE_PUBLIC size_t
vsce_phe_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_cipher_init(vsce_phe_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_cipher_cleanup(vsce_phe_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_cipher_t *
vsce_phe_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_cipher_delete(vsce_phe_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_cipher_new ()'.
//
VSCE_PUBLIC void
vsce_phe_cipher_destroy(vsce_phe_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_cipher_t *
vsce_phe_cipher_shallow_copy(vsce_phe_cipher_t *self);

//
//  Random used for salt generation
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_cipher_use_random(vsce_phe_cipher_t *self, vscf_impl_t *random);

//
//  Random used for salt generation
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_cipher_take_random(vsce_phe_cipher_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_cipher_release_random(vsce_phe_cipher_t *self);

//
//  Setups dependencies with default values.
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_setup_defaults(vsce_phe_cipher_t *self);

//
//  Returns buffer capacity needed to fit cipher text
//
VSCE_PUBLIC size_t
vsce_phe_cipher_encrypt_len(vsce_phe_cipher_t *self, size_t plain_text_len);

//
//  Returns buffer capacity needed to fit plain text
//
VSCE_PUBLIC size_t
vsce_phe_cipher_decrypt_len(vsce_phe_cipher_t *self, size_t cipher_text_len);

//
//  Encrypts data using account key
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_encrypt(vsce_phe_cipher_t *self, vsc_data_t plain_text, vsc_data_t account_key,
        vsc_buffer_t *cipher_text);

//
//  Decrypts data using account key
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_decrypt(vsce_phe_cipher_t *self, vsc_data_t cipher_text, vsc_data_t account_key,
        vsc_buffer_t *plain_text);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_CIPHER_H_INCLUDED
//  @end
