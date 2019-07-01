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
//  This module contains 'ecc public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecc_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_mbedtls_ecp.h"
#include "vscf_ecc_public_key_defs.h"
#include "vscf_ecc_public_key_internal.h"

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
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_ecc_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ecc_public_key_init_ctx(vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    self->impl_tag = vscf_impl_tag_ECC;
    mbedtls_ecp_group_init(&self->ecc_grp);
    mbedtls_ecp_point_init(&self->ecc_pub);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ecc_public_key_cleanup_ctx(vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->alg_info);
    mbedtls_ecp_group_free(&self->ecc_grp);
    mbedtls_ecp_point_free(&self->ecc_pub);
}

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_ecc_public_key_alg_id(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_mbedtls_ecp_group_id_to_alg_id(self->ecc_grp.id);
}

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ecc_public_key_alg_info(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->alg_info);

    return self->alg_info;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_ecc_public_key_len(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return self->ecc_grp.pbits / 8;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_ecc_public_key_bitlen(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return self->ecc_grp.pbits;
}

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_ecc_public_key_impl_tag(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);
    return self->impl_tag;
}

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_ecc_public_key_is_valid(const vscf_ecc_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->impl_tag != vscf_impl_tag_ECC) {
        return false;
    }

    const bool is_valid = mbedtls_ecp_check_pubkey(&self->ecc_grp, &self->ecc_pub) == 0;
    return is_valid;
}
