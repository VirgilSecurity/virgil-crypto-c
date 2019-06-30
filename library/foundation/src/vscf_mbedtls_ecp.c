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
//  Bridge between MbedTLS ECP module and virgil foundation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_ecp.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

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
//  Map "alg id" to correspond "mbedtls_ecp_group_id".
//
VSCF_PUBLIC mbedtls_ecp_group_id
vscf_mbedtls_ecp_group_id_from_alg_id(vscf_alg_id_t alg_id) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);

    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return MBEDTLS_ECP_DP_SECP256R1;
    default:
        return MBEDTLS_ECP_DP_NONE;
    }
}

//
//  Map "mbedtls_ecp_group_id" to correspond "alg id".
//
VSCF_PUBLIC vscf_alg_id_t
vscf_mbedtls_ecp_group_id_to_alg_id(mbedtls_ecp_group_id grp_id) {

    VSCF_ASSERT(grp_id != MBEDTLS_ECP_DP_NONE);

    switch (grp_id) {
    case MBEDTLS_ECP_DP_SECP256R1:
        return vscf_alg_id_SECP256R1;
    default:
        return vscf_alg_id_NONE;
    }
}

//
//  Validate if "alg id" belongs to ECC.
//
VSCF_PUBLIC vscf_status_t
vscf_mbedtls_ecp_group_load(vscf_alg_id_t alg_id, mbedtls_ecp_group *ecc_grp) {

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT_PTR(ecc_grp);

    const mbedtls_ecp_group_id grp_id = vscf_mbedtls_ecp_group_id_from_alg_id(alg_id);
    const int mbed_status = mbedtls_ecp_group_load(ecc_grp, grp_id);

    if (grp_id == MBEDTLS_ECP_DP_NONE || mbed_status != 0) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    return vscf_status_SUCCESS;
}
