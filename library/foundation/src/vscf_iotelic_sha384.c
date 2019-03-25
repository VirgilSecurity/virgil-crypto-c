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
//  This module contains 'iotelic sha384' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_iotelic_sha384.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_iotelic_sha384_defs.h"
#include "vscf_iotelic_sha384_internal.h"

// clang-format on
//  @end

#include <iotelic_sp_interface.h>
#include <virgil/crypto/common/vsc_buffer.h>

#include "vscf_simple_alg_info.h"
#include "vscf_alg_info.h"

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
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_iotelic_sha384_alg_id(const vscf_iotelic_sha384_t *self) {

    VSCF_UNUSED(self);

    return vscf_alg_id_SHA384;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_sha384_produce_alg_info(const vscf_iotelic_sha384_t *self) {

    VSCF_ASSERT_PTR(self);

    return NULL;
    //    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_iotelic_sha384_alg_id(self)));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_iotelic_sha384_restore_alg_info(vscf_iotelic_sha384_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    return vscf_error_UNSUPPORTED_ALGORITHM;

    //    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_iotelic_sha384_alg_id(self));

    //    return vscf_SUCCESS;
}

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_iotelic_sha384_hash(vsc_data_t data, vsc_buffer_t *digest) {

    size_t used_bytes = vsc_buffer_len(digest);

    vs_iot_execute_crypto_op(VS_IOT_HASH_SHA384, (void *)data.bytes, data.len, vsc_buffer_unused_bytes(digest),
            vsc_buffer_capacity(digest), &used_bytes);

    vsc_buffer_inc_used(digest, used_bytes);
}

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_iotelic_sha384_start(vscf_iotelic_sha384_t *self) {

    VSCF_UNUSED(self);

    VSCF_ASSERT(false); // TODO : not implemented yet
}

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_iotelic_sha384_update(vscf_iotelic_sha384_t *self, vsc_data_t data) {

    VSCF_UNUSED(self);
    VSCF_UNUSED(data);

    VSCF_ASSERT(false); // TODO : not implemented yet
}

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_iotelic_sha384_finish(vscf_iotelic_sha384_t *self, vsc_buffer_t *digest) {

    VSCF_UNUSED(self);
    VSCF_UNUSED(digest);

    VSCF_ASSERT(false); // TODO : not implemented yet
}
