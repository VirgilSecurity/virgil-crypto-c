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
//  This module contains 'pkcs5 pbes2' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs5_pbes2.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_cipher.h"
#include "vscf_pkcs5_pbes2_defs.h"
#include "vscf_pkcs5_pbes2_internal.h"

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
//  Note, this method is called automatically when method vscf_pkcs5_pbes2_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_pkcs5_pbes2_init_ctx(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs5_pbes2_cleanup_ctx(vscf_pkcs5_pbes2_t *pkcs5_pbes2) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);

    vsc_buffer_destroy(&pkcs5_pbes2->password);
}

//
//  Configure cipher with a new password.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_reset(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vsc_data_t pwd) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT(vsc_data_is_valid(pwd));

    vsc_buffer_destroy(&pkcs5_pbes2->password);
    pkcs5_pbes2->password = vsc_buffer_new_with_data(pwd);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs5_pbes2_encrypt(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher);
    VSCF_ASSERT_PTR(pkcs5_pbes2->pbkdf2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->password);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs5_pbes2_encrypted_len(pkcs5_pbes2, data.len));

    size_t key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(pkcs5_pbes2->cipher)));
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(key_len);
    vsc_buffer_make_secure(key);

    vscf_pkcs5_pbkdf2_derive(pkcs5_pbes2->pbkdf2, vsc_buffer_data(pkcs5_pbes2->password), key_len, key);

    vscf_cipher_set_key(pkcs5_pbes2->cipher, vsc_buffer_data(key));
    vscf_cipher_start_encryption(pkcs5_pbes2->cipher);
    vscf_cipher_update(pkcs5_pbes2->cipher, data, out);
    vscf_cipher_finish(pkcs5_pbes2->cipher, out);

    vsc_buffer_destroy(&key);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_encrypted_len(vscf_pkcs5_pbes2_t *pkcs5_pbes2, size_t data_len) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher);

    size_t len = vscf_cipher_encrypted_out_len(pkcs5_pbes2->cipher, data_len) +
                 vscf_cipher_encrypted_out_len(pkcs5_pbes2->cipher, 0);
    return len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs5_pbes2_decrypt(vscf_pkcs5_pbes2_t *pkcs5_pbes2, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher);
    VSCF_ASSERT_PTR(pkcs5_pbes2->pbkdf2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->password);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs5_pbes2_decrypted_len(pkcs5_pbes2, data.len));

    size_t key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(pkcs5_pbes2->cipher)));
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(key_len);
    vsc_buffer_make_secure(key);

    vscf_pkcs5_pbkdf2_derive(pkcs5_pbes2->pbkdf2, vsc_buffer_data(pkcs5_pbes2->password), key_len, key);

    vscf_cipher_set_key(pkcs5_pbes2->cipher, vsc_buffer_data(key));
    vscf_cipher_start_decryption(pkcs5_pbes2->cipher);
    vscf_cipher_update(pkcs5_pbes2->cipher, data, out);
    vscf_cipher_finish(pkcs5_pbes2->cipher, out);

    vsc_buffer_destroy(&key);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_decrypted_len(vscf_pkcs5_pbes2_t *pkcs5_pbes2, size_t data_len) {

    VSCF_ASSERT_PTR(pkcs5_pbes2);
    VSCF_ASSERT_PTR(pkcs5_pbes2->cipher);

    size_t len = vscf_cipher_decrypted_out_len(pkcs5_pbes2->cipher, data_len) +
                 vscf_cipher_decrypted_out_len(pkcs5_pbes2->cipher, 0);
    return len;
}
