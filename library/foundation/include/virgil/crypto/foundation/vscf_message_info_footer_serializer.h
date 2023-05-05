//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  Provide interface for "message info footer" class serialization.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_FOOTER_SERIALIZER_H_INCLUDED
#define VSCF_MESSAGE_INFO_FOOTER_SERIALIZER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_message_info_footer.h"
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
//  Contains API requirements of the interface 'message info footer serializer'.
//
typedef struct vscf_message_info_footer_serializer_api_t vscf_message_info_footer_serializer_api_t;

//
//  Return buffer size enough to hold serialized message info footer.
//
VSCF_PUBLIC size_t
vscf_message_info_footer_serializer_serialized_footer_len(vscf_impl_t *impl,
        const vscf_message_info_footer_t *message_info_footer);

//
//  Serialize class "message info footer".
//
VSCF_PUBLIC void
vscf_message_info_footer_serializer_serialize_footer(vscf_impl_t *impl,
        const vscf_message_info_footer_t *message_info_footer, vsc_buffer_t *out);

//
//  Deserialize class "message info footer".
//
VSCF_PUBLIC vscf_message_info_footer_t *
vscf_message_info_footer_serializer_deserialize_footer(vscf_impl_t *impl, vsc_data_t data, vscf_error_t *error);

//
//  Return message info footer serializer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_message_info_footer_serializer_api_t *
vscf_message_info_footer_serializer_api(const vscf_impl_t *impl);

//
//  Check if given object implements interface 'message info footer serializer'.
//
VSCF_PUBLIC bool
vscf_message_info_footer_serializer_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_message_info_footer_serializer_api_tag(
        const vscf_message_info_footer_serializer_api_t *message_info_footer_serializer_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_FOOTER_SERIALIZER_H_INCLUDED
//  @end
