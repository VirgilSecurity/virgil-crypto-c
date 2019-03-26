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
//  Provide interface for "message info" class serialization.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_SERIALIZER_H_INCLUDED
#define VSCF_MESSAGE_INFO_SERIALIZER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_message_info.h"
#include "vscf_error.h"
#include "vscf_api.h"

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
//  Contains API requirements of the interface 'message info serializer'.
//
typedef struct vscf_message_info_serializer_api_t vscf_message_info_serializer_api_t;

//
//  Return buffer size enough to hold serialized message info.
//
VSCF_PUBLIC size_t
vscf_message_info_serializer_serialized_len(vscf_impl_t *impl, const vscf_message_info_t *message_info);

//
//  Serialize class "message info".
//
VSCF_PUBLIC void
vscf_message_info_serializer_serialize(vscf_impl_t *impl, const vscf_message_info_t *message_info, vsc_buffer_t *out);

//
//  Read message info prefix from the given data, and if it is valid,
//  return a length of bytes of the whole message info.
//
//  Zero returned if length can not be determined from the given data,
//  and this means that there is no message info at the data beginning.
//
VSCF_PUBLIC size_t
vscf_message_info_serializer_read_prefix(vscf_impl_t *impl, vsc_data_t data);

//
//  Deserialize class "message info".
//
VSCF_PUBLIC vscf_message_info_t *
vscf_message_info_serializer_deserialize(vscf_impl_t *impl, vsc_data_t data, vscf_error_t *error);

//
//  Returns constant 'prefix len'.
//
VSCF_PUBLIC size_t
vscf_message_info_serializer_prefix_len(const vscf_message_info_serializer_api_t *message_info_serializer_api);

//
//  Return message info serializer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_message_info_serializer_api_t *
vscf_message_info_serializer_api(const vscf_impl_t *impl);

//
//  Check if given object implements interface 'message info serializer'.
//
VSCF_PUBLIC bool
vscf_message_info_serializer_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_message_info_serializer_api_tag(const vscf_message_info_serializer_api_t *message_info_serializer_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_SERIALIZER_H_INCLUDED
//  @end
