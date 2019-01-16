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
//  This module contains 'kdf alg info der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_kdf_alg_info_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_tag.h"
#include "vscf_kdf_alg_info.h"
#include "vscf_asn1_writer.h"
#include "vscf_kdf_alg_info_der_serializer_defs.h"
#include "vscf_kdf_alg_info_der_serializer_internal.h"

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
vscf_kdf_alg_info_der_serializer_setup_defaults(vscf_kdf_alg_info_der_serializer_t *kdf_alg_info_der_serializer) {

    //  TODO: This is STUB. Implement me.
    VSCF_ASSERT_PTR(kdf_alg_info_der_serializer);
    return vscf_SUCCESS;
}

//
//  Return buffer size enough to hold serialized algorithm
//
VSCF_PUBLIC size_t
vscf_kdf_alg_info_der_serializer_serialize_len(
        vscf_kdf_alg_info_der_serializer_t *kdf_alg_info_der_serializer, const vscf_impl_t *alg_info) {

    //  TODO: This is STUB. Implement me.
    VSCF_ASSERT_PTR(kdf_alg_info_der_serializer);
    VSCF_ASSERT_PTR(alg_info);
    return 0;
}

//
//  Serialize algorithm info to buffer class
//
VSCF_PUBLIC void
vscf_kdf_alg_info_der_serializer_serialize(vscf_kdf_alg_info_der_serializer_t *kdf_alg_info_der_serializer,
        const vscf_impl_t *alg_info, vsc_buffer_t *out) {

    //  TODO: This is STUB. Implement me.
    VSCF_ASSERT_PTR(kdf_alg_info_der_serializer);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT_PTR(out);
}
