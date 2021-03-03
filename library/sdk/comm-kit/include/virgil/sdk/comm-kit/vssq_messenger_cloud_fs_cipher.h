//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  File encryption and decryption to be used with the Cloud FS.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_CLOUD_FS_CIPHER_H_INCLUDED
#define VSSQ_MESSENGER_CLOUD_FS_CIPHER_H_INCLUDED

#include "vssq_library.h"
#include "vssq_status.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'messenger cloud fs cipher' context.
//
#ifndef VSSQ_MESSENGER_CLOUD_FS_CIPHER_T_DEFINED
#define VSSQ_MESSENGER_CLOUD_FS_CIPHER_T_DEFINED
    typedef struct vssq_messenger_cloud_fs_cipher_t vssq_messenger_cloud_fs_cipher_t;
#endif // VSSQ_MESSENGER_CLOUD_FS_CIPHER_T_DEFINED

//
//  Return size of 'vssq_messenger_cloud_fs_cipher_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_init(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_cleanup(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_cipher_t *
vssq_messenger_cloud_fs_cipher_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_delete(const vssq_messenger_cloud_fs_cipher_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_cipher_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_destroy(vssq_messenger_cloud_fs_cipher_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_cipher_t *
vssq_messenger_cloud_fs_cipher_shallow_copy(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_cipher_t *
vssq_messenger_cloud_fs_cipher_shallow_copy_const(const vssq_messenger_cloud_fs_cipher_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_use_random(vssq_messenger_cloud_fs_cipher_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_take_random(vssq_messenger_cloud_fs_cipher_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_cipher_release_random(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_setup_defaults(vssq_messenger_cloud_fs_cipher_t *self) VSSQ_NODISCARD;

//
//  Return key length for encrypt file.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_init_encryption_out_key_len(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Encryption initialization.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_init_encryption(vssq_messenger_cloud_fs_cipher_t *self,
        const vscf_impl_t *owner_private_key, size_t data_len, vsc_buffer_t *out_key) VSSQ_NODISCARD;

//
//  Return encryption header length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_start_encryption_out_len(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Start encryption and return header.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_start_encryption(vssq_messenger_cloud_fs_cipher_t *self,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return encryption process output buffer length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_process_encryption_out_len(vssq_messenger_cloud_fs_cipher_t *self, size_t data_len);

//
//  Encrypt data and return encrypted buffer.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_process_encryption(vssq_messenger_cloud_fs_cipher_t *self, vsc_data_t data,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return finish encryption data length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_finish_encryption_out_len(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Finish encryption and return last part of data.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_finish_encryption(vssq_messenger_cloud_fs_cipher_t *self,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return encryption footer length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_finish_encryption_footer_out_len(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Finish encryption and return footer data.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_finish_encryption_footer(vssq_messenger_cloud_fs_cipher_t *self,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Start decryption (Input - file encryption key).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_start_decryption(vssq_messenger_cloud_fs_cipher_t *self, vsc_data_t key) VSSQ_NODISCARD;

//
//  Return decryption data length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_process_decryption_out_len(vssq_messenger_cloud_fs_cipher_t *self, size_t data_len);

//
//  Decryption process.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_process_decryption(vssq_messenger_cloud_fs_cipher_t *self, vsc_data_t data,
        vsc_buffer_t *out) VSSQ_NODISCARD;

//
//  Return finish data part length.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_cipher_finish_decryption_out_len(vssq_messenger_cloud_fs_cipher_t *self);

//
//  Finish decryption and check sign.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_cloud_fs_cipher_finish_decryption(vssq_messenger_cloud_fs_cipher_t *self,
        const vscf_impl_t *owner_public_key, vsc_buffer_t *out) VSSQ_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_CLOUD_FS_CIPHER_H_INCLUDED
//  @end
