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
//  This module contains 'alg info der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_alg_info_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1wr.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info_der_serializer.h"
#include "vscf_kdf_alg_info_der_serializer.h"
#include "vscf_asn1_writer.h"
#include "vscf_alg_info_der_serializer_defs.h"
#include "vscf_alg_info_der_serializer_internal.h"

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
vscf_alg_info_der_serializer_setup_defaults(vscf_alg_info_der_serializer_t *alg_info_der_serializer) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);

    if (NULL == alg_info_der_serializer->asn1_writer) {
        vscf_alg_info_der_serializer_take_asn1_writer(alg_info_der_serializer, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }

    return vscf_SUCCESS;
}

//
//  Return buffer size enough to hold serialized algorithm
//
VSCF_PUBLIC size_t
vscf_alg_info_der_serializer_serialize_len(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(alg_info);

    return 128;
}

//
//  Serialize algorithm info to buffer class
//
VSCF_PUBLIC void
vscf_alg_info_der_serializer_serialize(
        vscf_alg_info_der_serializer_t *alg_info_der_serializer, const vscf_impl_t *alg_info, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(alg_info_der_serializer);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_alg_info_der_serializer_serialize_len(alg_info_der_serializer, alg_info));

    VSCF_ASSERT_PTR(alg_info_der_serializer->asn1_writer);

    //
    //  Route serialization.
    //
    vscf_alg_id_t alg_id = vscf_alg_info_alg_id(alg_info);
    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    vscf_simple_alg_info_der_serializer_t *simple_alg_info_serializer = NULL;
    vscf_kdf_alg_info_der_serializer_t *kdf_alg_info_serializer = NULL;

    switch (alg_id) {
    case vscf_alg_id_SHA224:
    case vscf_alg_id_SHA256:
    case vscf_alg_id_SHA384:
    case vscf_alg_id_SHA512:
    case vscf_alg_id_RSA:
    case vscf_alg_id_ED25519:
    case vscf_alg_id_X25519:
        simple_alg_info_serializer = vscf_simple_alg_info_der_serializer_new();
        vscf_simple_alg_info_der_serializer_use_asn1_writer(
                simple_alg_info_serializer, alg_info_der_serializer->asn1_writer);
        vscf_simple_alg_info_der_serializer_serialize(simple_alg_info_serializer, alg_info, out);
        vscf_simple_alg_info_der_serializer_destroy(&simple_alg_info_serializer);
        break;
    case vscf_alg_id_KDF1:
    case vscf_alg_id_KDF2:
        kdf_alg_info_serializer = vscf_kdf_alg_info_der_serializer_new();
        vscf_kdf_alg_info_der_serializer_use_asn1_writer(kdf_alg_info_serializer, alg_info_der_serializer->asn1_writer);
        vscf_kdf_alg_info_der_serializer_serialize(kdf_alg_info_serializer, alg_info, out);
        vscf_kdf_alg_info_der_serializer_destroy(&kdf_alg_info_serializer);
        break;
    case vscf_alg_id_NONE:
        VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
        break;
    }
}
