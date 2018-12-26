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
//  This module contains 'alg info der deserialize' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_deserialize.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_kdf1_alg_info.h"
#include "vscf_kdf2_alg_info.h"
#include "vscf_base_hash_alg.h"
#include "vscf_oid.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1_tag.h"
#include "vscf_alg.h"
#include "vscf_asn1_reader.h"
#include "vscf_alg_info.h"
#include "vscf_alg_info_der_deserialize_impl.h"
#include "vscf_alg_info_der_deserialize_internal.h"

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
//  Deserializer of algorithm information from buffer to public key in DER
//
VSCF_PUBLIC vscf_impl_t *
vscf_alg_info_der_deserialize_from_der_data(
        vscf_alg_info_der_deserialize_impl_t *alg_info_der_deserialize_impl, vsc_data_t der_data) {

    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl);
    VSCF_ASSERT(vsc_data_is_valid(der_data));
    VSCF_ASSERT_PTR(alg_info_der_deserialize_impl->asn1_reader);

    vscf_impl_t *asn1_reader = alg_info_der_deserialize_impl->asn1_reader;
    vscf_asn1_reader_reset(asn1_reader, der_data);

    vscf_asn1_reader_read_sequence(asn1_reader);

    int version = vscf_asn1_reader_read_int(asn1_reader);

    vscf_asn1_reader_read_sequence(asn1_reader);
    vsc_data_t oid = vscf_asn1_reader_read_oid(asn1_reader);
    vscf_alg_t alg = vscf_oid_to_alg(oid);

    vscf_impl_t *alg_info = NULL;

    if (alg == vscf_alg_KDF1) {
        vscf_kdf1_alg_info_impl_t *kdf1_alg_info = vscf_kdf1_alg_info_new();
        kdf1_alg_info->hash_alg = vscf_asn1_reader_read_int32(asn1_reader);
        alg_info = kdf1_alg_info;
    } else if (alg == vscf_alg_KDF2) {
        vscf_kdf2_alg_info_impl_t *kdf2_alg_info = vscf_kdf2_alg_info_new();
        kdf2_alg_info->hash_alg = vscf_asn1_reader_read_int32(asn1_reader);
        alg_info = kdf2_alg_info;
    }
    vscf_asn1_reader_read_null(asn1_reader);
    return alg_info;
}
