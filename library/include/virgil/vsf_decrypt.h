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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provide interface for data encryption.
// --------------------------------------------------------------------------

#ifndef VSF_DECRYPT_H_INCLUDED
#define VSF_DECRYPT_H_INCLUDED

#include "vsf_library.h"
#include "vsf_impl.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Contains API requirements of the interface 'decrypt'.
//
typedef struct vsf_decrypt_api_t vsf_decrypt_api_t;

//
//  Decrypt given data.
//
VSF_PUBLIC int
vsf_decrypt (vsf_impl_t* impl, const byte* enc, size_t enc_len, byte* data, size_t data_len,
        size_t* out_len);

//
//  Return decrypt API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_decrypt_api_t*
vsf_decrypt_api (vsf_impl_t* impl);

//
//  Return size of 'vsf_decrypt_api_t' type.
//
VSF_PUBLIC size_t
vsf_decrypt_api_size (void);

//
//  Check if given object implements interface 'decrypt'.
//
VSF_PUBLIC bool
vsf_decrypt_is_implemented (vsf_impl_t* impl);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_DECRYPT_H_INCLUDED
//  @end
