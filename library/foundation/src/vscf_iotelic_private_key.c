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
//  This module contains 'iotelic private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_iotelic_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_iotelic_public_key.h"
#include "vscf_iotelic_private_key_defs.h"
#include "vscf_iotelic_private_key_internal.h"

#include <iotelic_sp_interface.h>

// clang-format on
//  @end


#include <iotelic_sp_interface.h>
#include <vsc_buffer.h>
#include <iotelic/keypair.h>
#include <iotelic/ecdsa.h>
#include <common/iot_errno.h>


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
//  Note, this method is called automatically when method vscf_iotelic_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_iotelic_private_key_init_ctx(vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_iotelic_private_key_cleanup_ctx(vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.
}

//
//  Create private key with specific slot id.
//
VSCF_PUBLIC vscf_iotelic_private_key_t *
vscf_iotelic_private_key_new_with_slot_id(size_t slot_id) {

    vscf_iotelic_private_key_t *self = vscf_iotelic_private_key_new();

    self->slot_id = slot_id;

    return self;
}

//
//  Generate new private with a given slot id.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_generate_key(vscf_iotelic_private_key_t *self, size_t slot_id, vscf_alg_id_t alg_id) {

    VSCF_ASSERT_PTR(self);

    size_t sz;

    self->slot_id = slot_id;

    // Fill request to SP
    vs_keypair_cmd_t cmd;
    cmd.slot = slot_id;

    // Fill algorithm type
    switch (alg_id) {
    case vscf_alg_id_CURVE25519:
        cmd.keypair_type = KEYPAIR_EC_CURVE25519;
        break;
    case vscf_alg_id_ED25519:
        cmd.keypair_type = KEYPAIR_EC_ED25519;
        break;
    case KEYPAIR_EC_ED25519:
        cmd.keypair_type = KEYPAIR_EC_ED25519;
        break;
    default: { return vscf_status_ERROR_BAD_ARGUMENTS; }
    }

    if (ERR_OK != vs_iot_execute_crypto_op(VS_IOT_KEYPAIR_CREATE, (void *)&cmd, sizeof(cmd), 0, 0, &sz)) {
        return vscf_status_ERROR_KEY_GENERATION_FAILED;
    }

    return vscf_status_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_iotelic_private_key_alg_id(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return vscf_alg_id_NONE;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_private_key_produce_alg_info(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_restore_alg_info(vscf_iotelic_private_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_key_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_key_bitlen(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_signature_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_sign_hash(
        vscf_iotelic_private_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT_PTR(self);

    // Fill request to SP
    vs_ecdsa_sign_cmd_t cmd;
    cmd.slot = self->slot_id;

    // Fill hash type
    if (vscf_alg_id_SHA256 == hash_id) {
        cmd.hash_type = HASH_SHA_256;
    } else if (vscf_alg_id_SHA384 == hash_id) {
        cmd.hash_type = HASH_SHA_384;
    } else if (vscf_alg_id_SHA512 == hash_id) {
        cmd.hash_type = HASH_SHA_512;
    } else {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    // Fill hash data
    cmd.hash_data = hash_digest.bytes;
    cmd.hash_sz = hash_digest.len;

    size_t used_bytes = vsc_buffer_len(signature);

    if (ERR_OK != vs_iot_execute_crypto_op(VS_IOT_ECDSA_SIGN, (void *)&cmd, sizeof(cmd),
                          vsc_buffer_unused_bytes(signature), vsc_buffer_capacity(signature), &used_bytes)) {
        return vscf_status_ERROR_KEY_GENERATION_FAILED;
    }

    vsc_buffer_inc_used(signature, used_bytes);

    return vscf_status_SUCCESS;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_private_key_extract_public_key(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_export_private_key(const vscf_iotelic_private_key_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_exported_private_key_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_import_private_key(vscf_iotelic_private_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(data);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}
