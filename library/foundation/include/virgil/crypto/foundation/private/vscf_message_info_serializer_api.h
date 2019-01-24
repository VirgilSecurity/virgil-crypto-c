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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Interface 'message info serializer' API.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_SERIALIZER_API_H_INCLUDED
#define VSCF_MESSAGE_INFO_SERIALIZER_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_message_info.h"
#include "vscf_error_ctx.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
#endif

// clang-format on
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
//  Callback. Return buffer size enough to hold serialized message info.
//
typedef size_t (*vscf_message_info_serializer_api_serialized_len_fn)(vscf_impl_t *impl,
        const vscf_message_info_t *message_info);

//
//  Callback. Serialize class "message info".
//
typedef void (*vscf_message_info_serializer_api_serialize_fn)(vscf_impl_t *impl,
        const vscf_message_info_t *message_info, vsc_buffer_t *out);

//
//  Callback. Deserialize class "message info".
//
typedef const vscf_message_info_t * (*vscf_message_info_serializer_api_deserialize_fn)(vscf_impl_t *impl,
        vsc_data_t data, const vscf_error_ctx_t *error);

//
//  Contains API requirements of the interface 'message info serializer'.
//
struct vscf_message_info_serializer_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'message_info_serializer' MUST be equal to the 'vscf_api_tag_MESSAGE_INFO_SERIALIZER'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Return buffer size enough to hold serialized message info.
    //
    vscf_message_info_serializer_api_serialized_len_fn serialized_len_cb;
    //
    //  Serialize class "message info".
    //
    vscf_message_info_serializer_api_serialize_fn serialize_cb;
    //
    //  Deserialize class "message info".
    //
    vscf_message_info_serializer_api_deserialize_fn deserialize_cb;
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
#endif // VSCF_MESSAGE_INFO_SERIALIZER_API_H_INCLUDED
//  @end
