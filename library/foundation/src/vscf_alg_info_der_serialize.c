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
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  This module contains 'alg info der serialize' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_serialize.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_kdf1_alg_info.h"
#include "vscf_kdf2_alg_info.h"
#include "vscf_base_hash_alg.h"
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_tag.h"
#include "vscf_alg.h"
#include "vscf_asn1_writer.h"
#include "vscf_alg_info.h"
#include "vscf_alg_info_der_serialize_impl.h"
#include "vscf_alg_info_der_serialize_internal.h"

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
//  Serializer of algorithm information from public key in DER to buffer
//
VSCF_PUBLIC vscf_error_t
vscf_alg_info_der_serialize_to_der_data(vscf_alg_info_der_serialize_impl_t *alg_info_der_serialize_impl,
        const vscf_impl_t *alg_info, vsc_buffer_t *der_data) {

    VSCF_ASSERT_PTR(alg_info_der_serialize_impl);
    VSCF_ASSERT_PTR(der_data);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vsc_buffer_is_valid(der_data));
    VSCF_ASSERT_PTR(alg_info_der_serialize_impl->asn1_writer);

    vscf_impl_t *asn1_writer = alg_info_der_serialize_impl->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_ptr(der_data), vsc_buffer_left(der_data));

    vscf_alg_info_api_t *alg_info_api = vscf_alg_info_api(alg_info);

    vscf_alg_type_id_t alg_type_id = (vscf_alg_type_id_t)vscf_alg_info_alg_type_id(alg_info_api);

    size_t algorithm_count = 0;
    algorithm_count +=
            vscf_asn1_writer_write_oid(asn1_writer, vscf_oid_from_key_alg(vscf_alg_info_alg_type_id(alg_info_api)));

    switch (alg_type_id) {
    case vscf_alg_type_id_HASH:
        vscf_kdf1_alg_info_impl_t *kdf1_alg_info = (vscf_kdf1_alg_info_impl_t *)alg_info;
        vscf_asn1_writer_write_int32(asn1_writer, kdf1_alg_info->hash_alg);
        vscf_asn1_writer_write_int32(asn1_writer, kdf1_alg_info->hash_len);
        break;
    case vscf_alg_type_id_HASH:
        vscf_kdf2_alg_info_impl_t *kdf1_alg_info = (vscf_kdf2_alg_info_impl_t *)alg_info;
        vscf_asn1_writer_write_int32(asn1_writer, kdf2_alg_info->hash_alg);
        vscf_asn1_writer_write_int32(asn1_writer, kdf2_alg_info->hash_len);
        break;
    }
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    return vscf_SUCCESS;
}
