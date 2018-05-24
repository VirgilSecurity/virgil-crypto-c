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

#include "vsf_decrypt.h"
#include "vsf_assert.h"
#include "vsf_decrypt_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Decrypt given data.
//
VSF_PUBLIC int
vsf_decrypt (vsf_impl_t* impl, const byte* enc, size_t enc_len, byte* plain, size_t plain_len,
        size_t* out_len) {

    const vsf_decrypt_api_t *decrypt_api = vsf_decrypt_api (impl);
    VSF_ASSERT_PTR (decrypt_api);

    VSF_ASSERT_PTR (decrypt_api->decrypt_cb);
    return decrypt_api->decrypt_cb (impl, enc, enc_len, plain, plain_len, out_len);
}

//
//  Return decrypt API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_decrypt_api_t*
vsf_decrypt_api (vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    const vsf_api_t *api = vsf_impl_api (impl, vsf_api_tag_DECRYPT);
    return (const vsf_decrypt_api_t *) api;
}

//
//  Return size of 'vsf_decrypt_api_t' type.
//
VSF_PUBLIC size_t
vsf_decrypt_api_size (void) {

    return sizeof(vsf_decrypt_api_t);
}

//
//  Check if given object implements interface 'decrypt'.
//
VSF_PUBLIC bool
vsf_decrypt_is_implemented (vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    return vsf_impl_api (impl, vsf_api_tag_DECRYPT) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
