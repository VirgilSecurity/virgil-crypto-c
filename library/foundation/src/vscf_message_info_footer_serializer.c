//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


//  @description
// --------------------------------------------------------------------------
//  Provide interface for "message info footer" class serialization.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_footer_serializer.h"
#include "vscf_assert.h"
#include "vscf_message_info_footer_serializer_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return buffer size enough to hold serialized message info footer.
//
VSCF_PUBLIC size_t
vscf_message_info_footer_serializer_serialized_footer_len(vscf_impl_t *impl,
        const vscf_message_info_footer_t *message_info_footer) {

    const vscf_message_info_footer_serializer_api_t *message_info_footer_serializer_api = vscf_message_info_footer_serializer_api(impl);
    VSCF_ASSERT_PTR (message_info_footer_serializer_api);

    VSCF_ASSERT_PTR (message_info_footer_serializer_api->serialized_footer_len_cb);
    return message_info_footer_serializer_api->serialized_footer_len_cb (impl, message_info_footer);
}

//
//  Serialize class "message info footer".
//
VSCF_PUBLIC void
vscf_message_info_footer_serializer_serialize_footer(vscf_impl_t *impl,
        const vscf_message_info_footer_t *message_info_footer, vsc_buffer_t *out) {

    const vscf_message_info_footer_serializer_api_t *message_info_footer_serializer_api = vscf_message_info_footer_serializer_api(impl);
    VSCF_ASSERT_PTR (message_info_footer_serializer_api);

    VSCF_ASSERT_PTR (message_info_footer_serializer_api->serialize_footer_cb);
    message_info_footer_serializer_api->serialize_footer_cb (impl, message_info_footer, out);
}

//
//  Deserialize class "message info footer".
//
VSCF_PUBLIC vscf_message_info_footer_t *
vscf_message_info_footer_serializer_deserialize_footer(vscf_impl_t *impl, vsc_data_t data, vscf_error_t *error) {

    const vscf_message_info_footer_serializer_api_t *message_info_footer_serializer_api = vscf_message_info_footer_serializer_api(impl);
    VSCF_ASSERT_PTR (message_info_footer_serializer_api);

    VSCF_ASSERT_PTR (message_info_footer_serializer_api->deserialize_footer_cb);
    return message_info_footer_serializer_api->deserialize_footer_cb (impl, data, error);
}

//
//  Return message info footer serializer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_message_info_footer_serializer_api_t *
vscf_message_info_footer_serializer_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_MESSAGE_INFO_FOOTER_SERIALIZER);
    return (const vscf_message_info_footer_serializer_api_t *) api;
}

//
//  Check if given object implements interface 'message info footer serializer'.
//
VSCF_PUBLIC bool
vscf_message_info_footer_serializer_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_MESSAGE_INFO_FOOTER_SERIALIZER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_message_info_footer_serializer_api_tag(
        const vscf_message_info_footer_serializer_api_t *message_info_footer_serializer_api) {

    VSCF_ASSERT_PTR (message_info_footer_serializer_api);

    return message_info_footer_serializer_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
