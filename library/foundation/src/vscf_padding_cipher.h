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
//  Wraps any symmetric cipher algorithm to add padding to plaintext
//  to prevent message guessing attacks based on a ciphertext length.
// --------------------------------------------------------------------------

#ifndef VSCF_PADDING_CIPHER_H_INCLUDED
#define VSCF_PADDING_CIPHER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Handle 'padding cipher' context.
//
typedef struct vscf_padding_cipher_t vscf_padding_cipher_t;

//
//  Return size of 'vscf_padding_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_padding_cipher_init(vscf_padding_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_padding_cipher_cleanup(vscf_padding_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_padding_cipher_delete(vscf_padding_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_padding_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_padding_cipher_destroy(vscf_padding_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_padding_cipher_t *
vscf_padding_cipher_shallow_copy(vscf_padding_cipher_t *self);

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher);

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_padding_cipher_take_cipher(vscf_padding_cipher_t *self, vscf_impl_t *cipher);

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_cipher(vscf_padding_cipher_t *self);

//
//  Setup dependency to the interface 'padding' with shared ownership.
//
VSCF_PUBLIC void
vscf_padding_cipher_use_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding);

//
//  Setup dependency to the interface 'padding' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_padding_cipher_take_padding(vscf_padding_cipher_t *self, vscf_impl_t *padding);

//
//  Release dependency to the interface 'padding'.
//
VSCF_PUBLIC void
vscf_padding_cipher_release_padding(vscf_padding_cipher_t *self);

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_encryption(vscf_padding_cipher_t *self);

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_decryption(vscf_padding_cipher_t *self);

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_padding_cipher_update(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_out_len(vscf_padding_cipher_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_encrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_decrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len);

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_finish(vscf_padding_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PADDING_CIPHER_H_INCLUDED
//  @end
