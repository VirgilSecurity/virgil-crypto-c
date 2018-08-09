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
//  Interface 'hmac stream' API.
// --------------------------------------------------------------------------

#ifndef VSCF_HMAC_STREAM_API_H_INCLUDED
#define VSCF_HMAC_STREAM_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_hmac_info.h"
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
//  Callback. Reset HMAC.
//
typedef void (*vscf_hmac_stream_api_reset_fn)(vscf_impl_t *impl);

//
//  Callback. Start a new HMAC.
//
typedef void (*vscf_hmac_stream_api_start_fn)(vscf_impl_t *impl, const byte *key, size_t key_len);

//
//  Callback. Add given data to the HMAC.
//
typedef void (*vscf_hmac_stream_api_update_fn)(vscf_impl_t *impl, const byte *data, size_t data_len);

//
//  Callback. Accompilsh HMAC and return it's result (a message digest).
//
typedef void (*vscf_hmac_stream_api_finish_fn)(vscf_impl_t *impl, byte *hmac, size_t hmac_len);

//
//  Contains API requirements of the interface 'hmac stream'.
//
struct vscf_hmac_stream_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hmac_stream' MUST be equal to the 'vscf_api_tag_HMAC_STREAM'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Link to the inherited interface API 'hmac info'.
    //
    const vscf_hmac_info_api_t *hmac_info_api;
    //
    //  Reset HMAC.
    //
    vscf_hmac_stream_api_reset_fn reset_cb;
    //
    //  Start a new HMAC.
    //
    vscf_hmac_stream_api_start_fn start_cb;
    //
    //  Add given data to the HMAC.
    //
    vscf_hmac_stream_api_update_fn update_cb;
    //
    //  Accompilsh HMAC and return it's result (a message digest).
    //
    vscf_hmac_stream_api_finish_fn finish_cb;
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
#endif // VSCF_HMAC_STREAM_API_H_INCLUDED
//  @end
