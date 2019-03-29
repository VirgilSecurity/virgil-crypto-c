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
//  This module contains 'iotelic public key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_iotelic_public_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_iotelic_public_key_defs.h"
#include "vscf_iotelic_public_key_internal.h"

#include <iotelic_sp_interface.h>

// clang-format on
//  @end


#include <limits.h>
#include <vsc_buffer.h>
#include <iotelic/ecdsa.h>
#include <iotelic/keypair.h>
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
//  Note, this method is called automatically when method vscf_iotelic_public_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_iotelic_public_key_init_ctx(vscf_iotelic_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    self->keypair_type = KEYPAIR_INVALID;
    self->public_key = NULL;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_iotelic_public_key_cleanup_ctx(vscf_iotelic_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->public_key);
}

//
//  Import public key by using slot id.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_public_key_import_from_slot_id(vscf_iotelic_public_key_t *self, size_t slot_id) {

    VSCF_ASSERT_PTR(self);
    if (self->public_key)
        vsc_buffer_destroy(&self->public_key);

    vs_keypair_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.slot = slot_id;

    size_t sz;
    static const size_t MAX_PUBKEY_BUF = 128;
    self->public_key = vsc_buffer_new_with_capacity(MAX_PUBKEY_BUF);

    if (ERR_OK != vs_iot_execute_crypto_op(VS_IOT_KEYPAIR_GET_PUBLIC, (void *)&cmd, sizeof(cmd),
                          vsc_buffer_unused_bytes(self->public_key), vsc_buffer_capacity(self->public_key), &sz)) {
        vsc_buffer_destroy(&self->public_key);

        return vscf_status_ERROR_HSM_FAILED;
    }

    vsc_buffer_inc_used(self->public_key, sz);

    self->keypair_type = cmd.keypair_type;

    return vscf_status_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_iotelic_public_key_alg_id(const vscf_iotelic_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return vscf_alg_id_NONE;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_public_key_produce_alg_info(const vscf_iotelic_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_public_key_restore_alg_info(vscf_iotelic_public_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_iotelic_public_key_key_len(const vscf_iotelic_public_key_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->public_key && vsc_buffer_is_valid(self->public_key))
        return vsc_buffer_len(self->public_key);

    return 0;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_iotelic_public_key_key_bitlen(const vscf_iotelic_public_key_t *self) {

    return vscf_iotelic_public_key_key_len(self) * CHAR_BIT;
}

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_iotelic_public_key_verify_hash(
        vscf_iotelic_public_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(hash_digest);
    VSCF_UNUSED(hash_id);
    VSCF_UNUSED(signature);

    if (!self->public_key) {
        VSCF_ASSERT(false && "public key must be initialized before this call");
        return false;
    }

    vs_ecdsa_verify_cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));

    cmd.keypair_type = self->keypair_type;

    cmd.public_key = vsc_buffer_bytes(self->public_key);
    cmd.public_key_sz = vsc_buffer_len(self->public_key);

    cmd.hash = hash_digest.bytes;
    cmd.hash_sz = hash_digest.len;

    cmd.signature = signature.bytes;
    cmd.signature_sz = signature.len;

    switch (hash_id) {
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
        VSCF_ASSERT(false && "unsupported hash algorithm has been used");
        cmd.hash_type = HASH_SHA_INVALID;
        break;
    }

    switch (cmd.keypair_type) {
    case KEYPAIR_EC_SECP192R1:
    case KEYPAIR_EC_SECP224R1:
    case KEYPAIR_EC_SECP256R1:
    case KEYPAIR_EC_SECP384R1:
    case KEYPAIR_EC_SECP521R1:
    case KEYPAIR_EC_SECP192K1:
    case KEYPAIR_EC_SECP224K1:
    case KEYPAIR_EC_SECP256K1:
    case KEYPAIR_EC_CURVE25519:
    case KEYPAIR_EC_ED25519:
        cmd.sign_type = SIGN_COMMON;
        break;

    case KEYPAIR_RSA_2048:
    case KEYPAIR_RSA_3072:
    case KEYPAIR_RSA_4096:
        cmd.sign_type = SIGN_PSS;
        break;

    case KEYPAIR_INVALID:
    case KEYPAIR_MAX:
        VSCF_ASSERT(false && "incorrect keypair type");
        break;
    }

    bool res;
    size_t olen;
    res = vs_iot_execute_crypto_op(VS_IOT_ECDSA_VERIFY, (void *)&cmd, sizeof(cmd), NULL, 0, &olen) == ECDSA_VERIFY_OK;

    return res;
}

//
//  Export public key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_public_key_export_public_key(const vscf_iotelic_public_key_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);

    if (self->public_key) {
        VSCF_ASSERT(vsc_buffer_unused_len(out) >= vsc_buffer_len(self->public_key));

        vsc_buffer_write_data(out, vsc_buffer_data(self->public_key));

        return vscf_status_SUCCESS;
    } else {
        return vscf_status_ERROR_UNINITIALIZED;
    }
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_iotelic_public_key_exported_public_key_len(const vscf_iotelic_public_key_t *self) {

    return vscf_iotelic_public_key_key_len(self);
}

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_public_key_import_public_key(vscf_iotelic_public_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(data);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}
