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
//  Provide interface for authenticated data encryption.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_auth_encrypt.h"
#include "vsf_assert.h"
#include "vsf_auth_encrypt_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSF_PUBLIC vsf_error_t
vsf_auth_encrypt(vsf_impl_t* impl, const byte* data, size_t data_len, const byte* auth_data,
        size_t auth_data_len, byte* enc, size_t enc_len, size_t* out_len, byte* tag,
        size_t tag_len) {

    const vsf_auth_encrypt_api_t *auth_encrypt_api = vsf_auth_encrypt_api (impl);
    VSF_ASSERT_PTR (auth_encrypt_api);

    VSF_ASSERT_PTR (auth_encrypt_api->auth_encrypt_cb);
    return auth_encrypt_api->auth_encrypt_cb (impl, data, data_len, auth_data, auth_data_len, enc, enc_len, out_len, tag, tag_len);
}

//
//  Return auth encrypt API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_auth_encrypt_api_t*
vsf_auth_encrypt_api(vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    const vsf_api_t *api = vsf_impl_api (impl, vsf_api_tag_AUTH_ENCRYPT);
    return (const vsf_auth_encrypt_api_t *) api;
}

//
//  Check if given object implements interface 'auth encrypt'.
//
VSF_PUBLIC bool
vsf_auth_encrypt_is_implemented(vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    return vsf_impl_api (impl, vsf_api_tag_AUTH_ENCRYPT) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
