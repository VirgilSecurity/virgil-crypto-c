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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_x3dh.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"

#include <ed25519/ed25519.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>

// clang-format on
//  @end


// clang-format off

// VIRGIL_RATCHET_KDF_ROOT_INFO
static const uint8_t ratchet_kdf_root_info[] = {
        0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x52,
        0x41, 0x54, 0x43, 0x48, 0x45, 0x54, 0x5f, 0x4b,
        0x44, 0x46, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f,
        0x49, 0x4e, 0x46, 0x4f
};

// clang-format on


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


VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_initiator_x3dh_secret(const vscr_ratchet_private_key_t sender_identity_private_key,
        const vscr_ratchet_private_key_t sender_ephemeral_private_key,
        const vscr_ratchet_public_key_t receiver_identity_public_key,
        const vscr_ratchet_public_key_t receiver_long_term_public_key, bool receiver_has_one_time_key,
        const vscr_ratchet_public_key_t receiver_one_time_public_key, vscr_ratchet_symmetric_key_t shared_key) {

    size_t shared_secret_count = receiver_has_one_time_key ? 4 : 3;

        byte shared_secret_buf[4 * ED25519_DH_LEN];

        vsc_buffer_t shared_secret;
        vsc_buffer_init(&shared_secret);
        vsc_buffer_use(&shared_secret, shared_secret_buf, shared_secret_count * ED25519_DH_LEN);

        vscr_status_t status = vscr_status_SUCCESS;

        int curve_status = 0;
        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), receiver_long_term_public_key, sender_identity_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), receiver_identity_public_key, sender_ephemeral_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), receiver_long_term_public_key, sender_ephemeral_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        if (receiver_has_one_time_key) {
            curve_status = curve25519_key_exchange(
                    vsc_buffer_unused_bytes(&shared_secret), receiver_one_time_public_key, sender_ephemeral_private_key);
            vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

            if (curve_status != 0) {
                status = vscr_status_ERROR_CURVE25519;
                goto curve_err;
            }
        }

        vscr_ratchet_x3dh_derive_key(vsc_buffer_data(&shared_secret), shared_key);

    curve_err:
        vsc_buffer_delete(&shared_secret);

        vscr_zeroize(shared_secret_buf, sizeof(shared_secret_buf));

        return status;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_responder_x3dh_secret(const vscr_ratchet_public_key_t sender_identity_public_key,
        const vscr_ratchet_public_key_t sender_ephemeral_public_key,
        const vscr_ratchet_private_key_t receiver_identity_private_key,
        const vscr_ratchet_private_key_t receiver_long_term_private_key, bool receiver_has_one_time_key,
        const vscr_ratchet_private_key_t receiver_one_time_private_key, vscr_ratchet_symmetric_key_t shared_key) {

    size_t shared_secret_count = receiver_has_one_time_key ? 4 : 3;

        byte shared_secret_buf[4 * ED25519_DH_LEN];

        vsc_buffer_t shared_secret;
        vsc_buffer_init(&shared_secret);
        vsc_buffer_use(&shared_secret, shared_secret_buf, shared_secret_count * ED25519_DH_LEN);

        vscr_status_t status = vscr_status_SUCCESS;

        int curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), sender_identity_public_key, receiver_long_term_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), sender_ephemeral_public_key, receiver_identity_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(&shared_secret), sender_ephemeral_public_key, receiver_long_term_private_key);
        vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        if (receiver_has_one_time_key) {
            curve_status = curve25519_key_exchange(
                    vsc_buffer_unused_bytes(&shared_secret), sender_ephemeral_public_key, receiver_one_time_private_key);
            vsc_buffer_inc_used(&shared_secret, ED25519_DH_LEN);

            if (curve_status != 0) {
                status = vscr_status_ERROR_CURVE25519;
                goto curve_err;
            }
        }

        vscr_ratchet_x3dh_derive_key(vsc_buffer_data(&shared_secret), shared_key);

    curve_err:
        vsc_buffer_delete(&shared_secret);

        vscr_zeroize(shared_secret_buf, sizeof(shared_secret_buf));

        return status;
}

VSCR_PUBLIC void
vscr_ratchet_x3dh_derive_key(vsc_data_t shared_secret, vscr_ratchet_symmetric_key_t shared_key) {

    VSCR_ASSERT(shared_secret.len == 3 * ED25519_DH_LEN || shared_secret.len == 4 * ED25519_DH_LEN);

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, shared_key, vscr_ratchet_common_hidden_SHARED_KEY_LEN);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info)));

    vscf_hkdf_derive(hkdf, shared_secret, vscr_ratchet_common_hidden_SHARED_KEY_LEN, &buffer);
    vscf_hkdf_destroy(&hkdf);

    vsc_buffer_delete(&buffer);
}
