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
//  Mix-in interface that provides specific functionality to authenticated
//  encryption and decryption (AEAD ciphers).
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_cipher_auth.h"
#include "vscf_assert.h"
#include "vscf_cipher_auth_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Set additional data for for AEAD ciphers.
//
VSCF_PUBLIC void
vscf_cipher_auth_set_auth_data(vscf_impl_t *impl, vsc_data_t auth_data) {

    const vscf_cipher_auth_api_t *cipher_auth_api = vscf_cipher_auth_api(impl);
    VSCF_ASSERT_PTR (cipher_auth_api);

    VSCF_ASSERT_PTR (cipher_auth_api->set_auth_data_cb);
    cipher_auth_api->set_auth_data_cb (impl, auth_data);
}

//
//  Accomplish an authenticated encryption and place tag separately.
//
//  Note, if authentication tag should be added to an encrypted data,
//  method "finish" can be used.
//
VSCF_PUBLIC vscf_status_t
vscf_cipher_auth_finish_auth_encryption(vscf_impl_t *impl, vsc_buffer_t *out, vsc_buffer_t *tag) {

    const vscf_cipher_auth_api_t *cipher_auth_api = vscf_cipher_auth_api(impl);
    VSCF_ASSERT_PTR (cipher_auth_api);

    VSCF_ASSERT_PTR (cipher_auth_api->finish_auth_encryption_cb);
    return cipher_auth_api->finish_auth_encryption_cb (impl, out, tag);
}

//
//  Accomplish an authenticated decryption with explicitly given tag.
//
//  Note, if authentication tag is a part of an encrypted data then,
//  method "finish" can be used for simplicity.
//
VSCF_PUBLIC vscf_status_t
vscf_cipher_auth_finish_auth_decryption(vscf_impl_t *impl, vsc_data_t tag, vsc_buffer_t *out) {

    const vscf_cipher_auth_api_t *cipher_auth_api = vscf_cipher_auth_api(impl);
    VSCF_ASSERT_PTR (cipher_auth_api);

    VSCF_ASSERT_PTR (cipher_auth_api->finish_auth_decryption_cb);
    return cipher_auth_api->finish_auth_decryption_cb (impl, tag, out);
}

//
//  Return cipher auth API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_cipher_auth_api_t *
vscf_cipher_auth_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_CIPHER_AUTH);
    return (const vscf_cipher_auth_api_t *) api;
}

//
//  Return cipher API.
//
VSCF_PUBLIC const vscf_cipher_api_t *
vscf_cipher_auth_cipher_api(const vscf_cipher_auth_api_t *cipher_auth_api) {

    VSCF_ASSERT_PTR (cipher_auth_api);

    return cipher_auth_api->cipher_api;
}

//
//  Return cipher auth info API.
//
VSCF_PUBLIC const vscf_cipher_auth_info_api_t *
vscf_cipher_auth_cipher_auth_info_api(const vscf_cipher_auth_api_t *cipher_auth_api) {

    VSCF_ASSERT_PTR (cipher_auth_api);

    return cipher_auth_api->cipher_auth_info_api;
}

//
//  Return auth encrypt API.
//
VSCF_PUBLIC const vscf_auth_encrypt_api_t *
vscf_cipher_auth_auth_encrypt_api(const vscf_cipher_auth_api_t *cipher_auth_api) {

    VSCF_ASSERT_PTR (cipher_auth_api);

    return cipher_auth_api->auth_encrypt_api;
}

//
//  Return auth decrypt API.
//
VSCF_PUBLIC const vscf_auth_decrypt_api_t *
vscf_cipher_auth_auth_decrypt_api(const vscf_cipher_auth_api_t *cipher_auth_api) {

    VSCF_ASSERT_PTR (cipher_auth_api);

    return cipher_auth_api->auth_decrypt_api;
}

//
//  Check if given object implements interface 'cipher auth'.
//
VSCF_PUBLIC bool
vscf_cipher_auth_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_CIPHER_AUTH) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_cipher_auth_api_tag(const vscf_cipher_auth_api_t *cipher_auth_api) {

    VSCF_ASSERT_PTR (cipher_auth_api);

    return cipher_auth_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
