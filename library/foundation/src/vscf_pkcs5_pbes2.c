//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_encrypt.h"
#include "vscf_alg_factory.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_aes256_gcm.h"
#include "vscf_pbe_alg_info.h"
#include "vscf_salted_kdf.h"
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
vscf_pkcs5_pbes2_init_ctx(vscf_pkcs5_pbes2_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs5_pbes2_cleanup_ctx(vscf_pkcs5_pbes2_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->password);
}

//
//  Configure cipher with a new password.
//
VSCF_PUBLIC void
vscf_pkcs5_pbes2_reset(vscf_pkcs5_pbes2_t *self, vsc_data_t pwd) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(pwd));

    vsc_buffer_destroy(&self->password);
    self->password = vsc_buffer_new_with_data(pwd);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_pkcs5_pbes2_alg_id(const vscf_pkcs5_pbes2_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_PKCS5_PBES2;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs5_pbes2_produce_alg_info(const vscf_pkcs5_pbes2_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->cipher);

    vscf_impl_t *kdf_alg_info = vscf_alg_produce_alg_info(self->kdf);
    vscf_impl_t *cipher_alg_info = vscf_alg_produce_alg_info(self->cipher);

    vscf_impl_t *pbes2_alg_info = vscf_pbe_alg_info_impl(
            vscf_pbe_alg_info_new_with_members(vscf_alg_id_PKCS5_PBES2, &kdf_alg_info, &cipher_alg_info));

    return pbes2_alg_info;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs5_pbes2_restore_alg_info(vscf_pkcs5_pbes2_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_PKCS5_PBES2);

    const vscf_pbe_alg_info_t *pbe_alg_info = (const vscf_pbe_alg_info_t *)alg_info;

    vscf_impl_t *kdf = vscf_alg_factory_create_kdf_from_info(vscf_pbe_alg_info_kdf_alg_info(pbe_alg_info));
    vscf_impl_t *cipher = vscf_alg_factory_create_cipher_from_info(vscf_pbe_alg_info_cipher_alg_info(pbe_alg_info));

    vscf_pkcs5_pbes2_release_kdf(self);
    vscf_pkcs5_pbes2_release_cipher(self);

    vscf_pkcs5_pbes2_take_kdf(self, kdf);
    vscf_pkcs5_pbes2_take_cipher(self, cipher);

    return vscf_status_SUCCESS;
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs5_pbes2_encrypt(vscf_pkcs5_pbes2_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->password);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs5_pbes2_encrypted_len(self, data.len));

    size_t key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(key_len);
    vsc_buffer_make_secure(key);

    vscf_kdf_derive(self->kdf, vsc_buffer_data(self->password), key_len, key);

    vscf_cipher_set_key(self->cipher, vsc_buffer_data(key));
    vscf_cipher_start_encryption(self->cipher);
    vscf_cipher_update(self->cipher, data, out);
    vscf_status_t status = vscf_cipher_finish(self->cipher, out);

    vsc_buffer_destroy(&key);

    return status;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_encrypted_len(const vscf_pkcs5_pbes2_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    size_t len = vscf_cipher_encrypted_out_len(self->cipher, data_len) + vscf_cipher_encrypted_out_len(self->cipher, 0);
    return len;
}

//
//  Precise length calculation of encrypted data.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_precise_encrypted_len(const vscf_pkcs5_pbes2_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    size_t len = vscf_encrypt_precise_encrypted_len(self->cipher, data_len);
    return len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs5_pbes2_decrypt(vscf_pkcs5_pbes2_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->password);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs5_pbes2_decrypted_len(self, data.len));

    size_t key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(key_len);
    vsc_buffer_make_secure(key);

    vscf_kdf_derive(self->kdf, vsc_buffer_data(self->password), key_len, key);

    vscf_cipher_set_key(self->cipher, vsc_buffer_data(key));
    vscf_cipher_start_decryption(self->cipher);
    vscf_cipher_update(self->cipher, data, out);
    vscf_status_t status = vscf_cipher_finish(self->cipher, out);

    vsc_buffer_destroy(&key);

    return status;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_pkcs5_pbes2_decrypted_len(const vscf_pkcs5_pbes2_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    size_t len = vscf_cipher_decrypted_out_len(self->cipher, data_len) + vscf_cipher_decrypted_out_len(self->cipher, 0);
    return len;
}
