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
//  This module contains 'alg info der deserializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_deserializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_oid.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1_tag.h"
#include "vscf_alg_id.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_kdf_alg_info.h"
#include "vscf_alg_info_compatible.h"
#include "vscf_asn1_reader.h"
#include "vscf_alg_info_der_deserializer_defs.h"
#include "vscf_alg_info_der_deserializer_internal.h"

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
vscf_alg_info_der_deserializer_setup_defaults(vscf_alg_info_der_deserializer_t *alg_info_der_deserializer) {

    VSCF_ASSERT_PTR(alg_info_der_deserializer);

    if (NULL == alg_info_der_deserializer->asn1_reader) {
        vscf_alg_info_der_deserializer_take_asn1_reader(alg_info_der_deserializer, vscf_asn1rd_impl(vscf_asn1rd_new()));
    }

    return vscf_SUCCESS;
}

//
//  Algorithm deserialization algorithm from data
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserializer_deserialize(
        vscf_alg_info_der_deserializer_t *alg_info_der_deserializer, vsc_data_t data) {

    VSCF_ASSERT_PTR(alg_info_der_deserializer);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(alg_info_der_deserializer->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserializer->asn1_reader;

    vscf_asn1_reader_reset(asn1_reader, data);

    vsc_data_t alg_oid = vscf_asn1_reader_read_oid(asn1_reader);

    vscf_asn1_reader_read_null(asn1_reader);

    vscf_alg_id_t alg_id = vscf_oid_to_alg_id(alg_oid);

    if (alg_id == vscf_alg_id_SHA256) {
        vscf_simple_alg_info_t *simple_alg = vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA256);
        return vscf_simple_alg_info_impl(simple_alg);
    }

    if (alg_id == vscf_alg_id_KDF1) {
        vscf_simple_alg_info_t *simple_alg = vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA256);
        vscf_kdf_alg_info_t *kdf_alg = vscf_kdf_alg_info_new_with_members(vscf_alg_id_KDF1, simple_alg);
        return vscf_kdf_alg_info_impl(kdf_alg);
    }

    return NULL;
}
