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
//  Provide interface for authenticated data encryption.
// --------------------------------------------------------------------------

#ifndef VSCF_AUTH_ENCRYPT_H_INCLUDED
#define VSCF_AUTH_ENCRYPT_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_error.h"
#include "vscf_api.h"

#include <virgil/crypto/common/vsc_data.h>
#include <virgil/crypto/common/vsc_buffer.h>
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
//  Contains API requirements of the interface 'auth encrypt'.
//
typedef struct vscf_auth_encrypt_api_t vscf_auth_encrypt_api_t;

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSCF_PUBLIC vscf_error_t
vscf_auth_encrypt(vscf_impl_t *impl, vsc_data_t data, vsc_data_t auth_data, vsc_buffer_t *out, vsc_buffer_t *tag);

//
//  Calculate required buffer length to hold the authenticated encrypted data.
//
VSCF_PUBLIC size_t
vscf_auth_encrypt_auth_encrypted_len(vscf_impl_t *impl, size_t data_len);

//
//  Return auth encrypt API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_auth_encrypt_api_t *
vscf_auth_encrypt_api(vscf_impl_t *impl);

//
//  Check if given object implements interface 'auth encrypt'.
//
VSCF_PUBLIC bool
vscf_auth_encrypt_is_implemented(vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_auth_encrypt_api_tag(const vscf_auth_encrypt_api_t *auth_encrypt_api);

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_auth_encrypt_impl_tag(const vscf_auth_encrypt_api_t *auth_encrypt_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_AUTH_ENCRYPT_H_INCLUDED
//  @end
