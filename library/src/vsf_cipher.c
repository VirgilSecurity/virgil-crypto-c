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
//  Provide interface for symmetric ciphers.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_cipher.h"
#include "vsf_assert.h"
#include "vsf_cipher_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Returns nonce length in bytes, or 0 if nonce is not required.
//
VSF_PUBLIC size_t
vsf_cipher_nonce_len (vsf_impl_t* impl) {

    const vsf_cipher_api_t *cipher_api = vsf_cipher_api (impl);
    VSF_ASSERT_PTR (cipher_api);

    VSF_ASSERT_PTR (cipher_api->nonce_len_cb);
    return cipher_api->nonce_len_cb (impl);
}

//
//  Setup IV or nonce.
//
VSF_PUBLIC void
vsf_cipher_set_nonce (vsf_impl_t* impl, const byte* nonce, size_t nonce_len) {

    const vsf_cipher_api_t *cipher_api = vsf_cipher_api (impl);
    VSF_ASSERT_PTR (cipher_api);

    VSF_ASSERT_PTR (cipher_api->set_nonce_cb);
    cipher_api->set_nonce_cb (impl, nonce, nonce_len);
}

//
//  Set padding mode, for cipher modes that use padding.
//
VSF_PUBLIC void
vsf_cipher_set_padding (vsf_impl_t* impl, vsf_cipher_padding_t padding) {

    const vsf_cipher_api_t *cipher_api = vsf_cipher_api (impl);
    VSF_ASSERT_PTR (cipher_api);

    VSF_ASSERT_PTR (cipher_api->set_padding_cb);
    cipher_api->set_padding_cb (impl, padding);
}

//
//  Return cipher API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_cipher_api_t*
vsf_cipher_api (vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    const vsf_api_t *api = vsf_impl_api (impl, vsf_api_tag_CIPHER);
    return (const vsf_cipher_api_t *) api;
}

//
//  Return size of 'vsf_cipher_api_t' type.
//
VSF_PUBLIC size_t
vsf_cipher_api_size (void) {

    return sizeof(vsf_cipher_api_t);
}

//
//  Check if given object implements interface 'cipher'.
//
VSF_PUBLIC bool
vsf_cipher_is_implemented (vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    return vsf_impl_api (impl, vsf_api_tag_CIPHER) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
