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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'message info der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_message_info_der_serializer_defs.h"
#include "vscf_message_info_der_serializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_setup_defaults(vscf_message_info_der_serializer_t *message_info_der_serializer) {

    VSCF_ASSERT_PTR(message_info_der_serializer);

    if (NULL == message_info_der_serializer->asn1_reader) {
        message_info_der_serializer->asn1_reader = vscf_asn1rd_impl(vscf_asn1rd_new());
    }

    if (NULL == message_info_der_serializer->asn1_writer) {
        message_info_der_serializer->asn1_writer = vscf_asn1wr_impl(vscf_asn1wr_new());
    }

    return vscf_SUCCESS;
}

//
//  Return buffer size enough to hold serialized message info.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_serialized_len(
        vscf_message_info_der_serializer_t *message_info_der_serializer, const vscf_message_info_t *message_info) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);

    //  TODO: This is STUB. Implement me.

    return 1024;
}

//
//  Serialize class "message info".
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_serialize(vscf_message_info_der_serializer_t *message_info_der_serializer,
        const vscf_message_info_t *message_info, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT_PTR(message_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(out));

    //  TODO: This is STUB. Implement me.
}

//
//  Deserialize class "message info".
//
VSCF_PUBLIC const vscf_message_info_t *
vscf_message_info_der_serializer_deserialize(vscf_message_info_der_serializer_t *message_info_der_serializer,
        vsc_data_t data, const vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(message_info_der_serializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_UNUSED(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}
