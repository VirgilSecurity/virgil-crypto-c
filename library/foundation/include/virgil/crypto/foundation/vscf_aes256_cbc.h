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
//  This module contains 'aes256 cbc' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_AES256_CBC_H_INCLUDED
#define VSCF_AES256_CBC_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_cipher_info.h"
#include "vscf_alg_id.h"
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
//  Public integral constants.
//
enum {
    //
    //  Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    //
    vscf_aes256_cbc_NONCE_LEN = 16,
    //
    //  Cipher key length in bytes.
    //
    vscf_aes256_cbc_KEY_LEN = 32,
    //
    //  Cipher key length in bits.
    //
    vscf_aes256_cbc_KEY_BITLEN = 256,
    //
    //  Cipher block length in bytes.
    //
    vscf_aes256_cbc_BLOCK_LEN = 16
};

//
//  Handles implementation details.
//
typedef struct vscf_aes256_cbc_t vscf_aes256_cbc_t;

//
//  Return size of 'vscf_aes256_cbc_t' type.
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes256_cbc_impl(vscf_aes256_cbc_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_aes256_cbc_impl_const(const vscf_aes256_cbc_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_aes256_cbc_init(vscf_aes256_cbc_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_aes256_cbc_init()'.
//
VSCF_PUBLIC void
vscf_aes256_cbc_cleanup(vscf_aes256_cbc_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_aes256_cbc_t *
vscf_aes256_cbc_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_cbc_new()'.
//
VSCF_PUBLIC void
vscf_aes256_cbc_delete(vscf_aes256_cbc_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_cbc_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_aes256_cbc_destroy(vscf_aes256_cbc_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_aes256_cbc_t *
vscf_aes256_cbc_shallow_copy(vscf_aes256_cbc_t *self);

//
//  Returns instance of the implemented interface 'cipher info'.
//
VSCF_PUBLIC const vscf_cipher_info_api_t *
vscf_aes256_cbc_cipher_info_api(void);

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_aes256_cbc_alg_id(const vscf_aes256_cbc_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes256_cbc_produce_alg_info(const vscf_aes256_cbc_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_cbc_restore_alg_info(vscf_aes256_cbc_t *self, const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_cbc_encrypt(vscf_aes256_cbc_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_encrypted_len(vscf_aes256_cbc_t *self, size_t data_len);

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_cbc_decrypt(vscf_aes256_cbc_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_decrypted_len(vscf_aes256_cbc_t *self, size_t data_len);

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_aes256_cbc_set_nonce(vscf_aes256_cbc_t *self, vsc_data_t nonce);

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_aes256_cbc_set_key(vscf_aes256_cbc_t *self, vsc_data_t key);

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_aes256_cbc_start_encryption(vscf_aes256_cbc_t *self);

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_aes256_cbc_start_decryption(vscf_aes256_cbc_t *self);

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_aes256_cbc_update(vscf_aes256_cbc_t *self, vsc_data_t data, vsc_buffer_t *out);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_out_len(vscf_aes256_cbc_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_encrypted_out_len(vscf_aes256_cbc_t *self, size_t data_len);

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_cbc_decrypted_out_len(vscf_aes256_cbc_t *self, size_t data_len);

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_cbc_finish(vscf_aes256_cbc_t *self, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_AES256_CBC_H_INCLUDED
//  @end
