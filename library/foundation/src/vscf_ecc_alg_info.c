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
//  This module contains 'ecc alg info' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecc_alg_info.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_ecc_alg_info_defs.h"
#include "vscf_ecc_alg_info_internal.h"

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
//  Note, this method is called automatically when method vscf_ecc_alg_info_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ecc_alg_info_init_ctx(vscf_ecc_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_id = vscf_alg_id_NONE;
    self->key_id = vscf_oid_id_NONE;
    self->domain_id = vscf_oid_id_NONE;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ecc_alg_info_cleanup_ctx(vscf_ecc_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Create algorithm info with EC generic key identificator, EC domain group identificator.
//
VSCF_PUBLIC void
vscf_ecc_alg_info_init_ctx_with_members(vscf_ecc_alg_info_t *self, vscf_alg_id_t alg_id, vscf_oid_id_t key_id,
        vscf_oid_id_t domain_id) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(key_id != vscf_oid_id_NONE);
    VSCF_ASSERT(domain_id != vscf_oid_id_NONE);

    self->key_id = key_id;
    self->domain_id = domain_id;
    self->alg_id = alg_id;
}

//
//  Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
//
VSCF_PUBLIC vscf_oid_id_t
vscf_ecc_alg_info_key_id(const vscf_ecc_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->key_id != vscf_oid_id_NONE);

    return self->key_id;
}

//
//  Return EC domain group identificator.
//
VSCF_PUBLIC vscf_oid_id_t
vscf_ecc_alg_info_domain_id(const vscf_ecc_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->domain_id != vscf_oid_id_NONE);

    return self->domain_id;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_ecc_alg_info_alg_id(const vscf_ecc_alg_info_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->alg_id != vscf_alg_id_NONE);

    return self->alg_id;
}
