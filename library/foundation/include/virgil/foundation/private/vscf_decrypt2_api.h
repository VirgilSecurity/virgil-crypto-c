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
//  Interface 'decrypt2' API.
// --------------------------------------------------------------------------

#ifndef VSCF_DECRYPT2_API_H_INCLUDED
#define VSCF_DECRYPT2_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_api.h"
#include "vscf_impl.h"

#include <virgil/common/vsc_data.h>
#include <virgil/common/vsc_buffer.h>
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
//  Callback. Decrypt given data.
//
typedef vscf_error_t (*vscf_decrypt2_api_decrypt_fn)(vscf_impl_t *impl, const vsc_data_t data, vsc_buffer_t *out);

//
//  Callback. Calculate required buffer length to hold the decrypted data.
//
typedef size_t (*vscf_decrypt2_api_decrypted_len_fn)(vscf_impl_t *impl);

//
//  Contains API requirements of the interface 'decrypt2'.
//
struct vscf_decrypt2_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'decrypt2' MUST be equal to the 'vscf_api_tag_DECRYPT2'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Decrypt given data.
    //
    vscf_decrypt2_api_decrypt_fn decrypt_cb;
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    vscf_decrypt2_api_decrypted_len_fn decrypted_len_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_DECRYPT2_API_H_INCLUDED
//  @end
