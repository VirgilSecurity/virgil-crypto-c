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
//  This module contains 'iotelic hmac' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_iotelic_hmac.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_hash.h"
#include "vscf_iotelic_hmac_defs.h"
#include "vscf_iotelic_hmac_internal.h"

// clang-format on
//  @end

#include <iotelic_sp_interface.h>
#include <vsc_buffer.h>
#include <iotelic/hmac.h>

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
//  Note, this method is called automatically when method vscf_iotelic_hmac_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_iotelic_hmac_init_ctx(vscf_iotelic_hmac_t *self) {
    //  TODO: This is STUB. Implement me.
    (void)self;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_iotelic_hmac_cleanup_ctx(vscf_iotelic_hmac_t *self) {
    //  TODO: This is STUB. Implement me.
    (void)self;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_iotelic_hmac_alg_id(const vscf_iotelic_hmac_t *self) {

    VSCF_UNUSED(self);

    return vscf_alg_id_HMAC;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_hmac_produce_alg_info(const vscf_iotelic_hmac_t *self) {

    VSCF_UNUSED(self);

    return NULL;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_iotelic_hmac_restore_alg_info(vscf_iotelic_hmac_t *self, const vscf_impl_t *alg_info) {

    VSCF_UNUSED(self);
    VSCF_UNUSED(alg_info);

    return vscf_error_BAD_ARGUMENTS;
}

//
//  Size of the digest (mac output) in bytes.
//
VSCF_PUBLIC size_t
vscf_iotelic_hmac_digest_len(vscf_iotelic_hmac_t *self) {
    //  TODO: This is STUB. Implement me.

    VSCF_UNUSED(self);
    return 0;
}

//
//  Calculate MAC over given data.
//
VSCF_PUBLIC void
vscf_iotelic_hmac_mac(vscf_iotelic_hmac_t *self, vsc_data_t key, vsc_data_t data, vsc_buffer_t *mac) {
    hmac_cmd_t cmd;
    size_t used_bytes = vsc_buffer_len(mac);

    cmd.key = key.bytes;
    cmd.key_sz = key.len;
    cmd.input = data.bytes;
    cmd.input_sz = data.len;

    switch (vscf_alg_alg_id(self->hash)) {
    case vscf_alg_id_SHA256:
        cmd.hash_type = HASH_SHA_256;
        break;
    case vscf_alg_id_SHA384:
        cmd.hash_type = HASH_SHA_384;
        break;
    case vscf_alg_id_SHA512:
        cmd.hash_type = HASH_SHA_512;
        break;
    default:
        cmd.hash_type = HASH_SHA_INVALID;
        VSCF_ASSERT(false);
        break;
    }

    vs_iot_execute_crypto_op(VS_IOT_HMAC, (void *)&cmd, sizeof(cmd), vsc_buffer_unused_bytes(mac),
            vsc_buffer_capacity(mac), &used_bytes);

    vsc_buffer_inc_used(mac, used_bytes);
}

//
//  Start a new MAC.
//
VSCF_PUBLIC void
vscf_iotelic_hmac_start(vscf_iotelic_hmac_t *self, vsc_data_t key) {
    //  TODO: This is STUB. Implement me.

    VSCF_UNUSED(self);
    VSCF_UNUSED(key);
}

//
//  Add given data to the MAC.
//
VSCF_PUBLIC void
vscf_iotelic_hmac_update(vscf_iotelic_hmac_t *self, vsc_data_t data) {
    //  TODO: This is STUB. Implement me.

    VSCF_UNUSED(self);
    VSCF_UNUSED(data);
}

//
//  Accomplish MAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_iotelic_hmac_finish(vscf_iotelic_hmac_t *self, vsc_buffer_t *mac) {
    //  TODO: This is STUB. Implement me.

    VSCF_UNUSED(self);
    VSCF_UNUSED(mac);
}

//
//  Prepare to authenticate a new message with the same key
//  as the previous MAC operation.
//
VSCF_PUBLIC void
vscf_iotelic_hmac_reset(vscf_iotelic_hmac_t *self) {
    //  TODO: This is STUB. Implement me.

    VSCF_UNUSED(self);
}
