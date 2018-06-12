//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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


//  @description
// --------------------------------------------------------------------------
//  Provide interface for data encryption.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_encrypt.h"
#include "vscf_assert.h"
#include "vscf_encrypt_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_encrypt(vscf_impl_t* impl, const byte* data, size_t data_len, byte* enc, size_t enc_len, size_t* out_len) {

    const vscf_encrypt_api_t *encrypt_api = vscf_encrypt_api (impl);
    VSCF_ASSERT_PTR (encrypt_api);

    VSCF_ASSERT_PTR (encrypt_api->encrypt_cb);
    return encrypt_api->encrypt_cb (impl, data, data_len, enc, enc_len, out_len);
}

//
//  Calculate required buffer length to hold the encrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to hold auth tag as well.
//
VSCF_PUBLIC size_t
vscf_encrypt_required_enc_len(vscf_impl_t* impl, size_t data_len, size_t auth_tag_len) {

    const vscf_encrypt_api_t *encrypt_api = vscf_encrypt_api (impl);
    VSCF_ASSERT_PTR (encrypt_api);

    VSCF_ASSERT_PTR (encrypt_api->required_enc_len_cb);
    return encrypt_api->required_enc_len_cb (impl, data_len, auth_tag_len);
}

//
//  Return encrypt API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_encrypt_api_t*
vscf_encrypt_api(vscf_impl_t* impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_ENCRYPT);
    return (const vscf_encrypt_api_t *) api;
}

//
//  Check if given object implements interface 'encrypt'.
//
VSCF_PUBLIC bool
vscf_encrypt_is_implemented(vscf_impl_t* impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_ENCRYPT) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
