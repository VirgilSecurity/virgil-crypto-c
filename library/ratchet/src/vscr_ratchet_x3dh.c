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

#include <ed25519/ed25519.h>

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


VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_initiator_x3dh_secret(const vscr_ratchet_private_key_t sender_identity_private_key,
        const vscr_ratchet_private_key_t sender_ephemeral_private_key,
        const vscr_ratchet_public_key_t receiver_identity_public_key,
        const vscr_ratchet_public_key_t receiver_long_term_public_key, bool receiver_has_one_time_key,
        const vscr_ratchet_public_key_t receiver_one_time_public_key, vsc_buffer_t *shared_secret) {

    size_t shared_secret_count = receiver_has_one_time_key ? 4 : 3;

        VSCR_ASSERT(vsc_buffer_capacity(shared_secret) >= shared_secret_count * ED25519_DH_LEN);

        vscr_status_t status = vscr_status_SUCCESS;

        int curve_status = 0;
        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), receiver_long_term_public_key, sender_identity_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), receiver_identity_public_key, sender_ephemeral_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), receiver_long_term_public_key, sender_ephemeral_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        if (receiver_has_one_time_key) {
            curve_status = curve25519_key_exchange(
                    vsc_buffer_unused_bytes(shared_secret), receiver_one_time_public_key, sender_ephemeral_private_key);
            vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

            if (curve_status != 0) {
                status = vscr_status_ERROR_CURVE25519;
                goto curve_err;
            }
        }

    curve_err:
        return status;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_responder_x3dh_secret(const vscr_ratchet_public_key_t sender_identity_public_key,
        const vscr_ratchet_public_key_t sender_ephemeral_public_key,
        const vscr_ratchet_private_key_t receiver_identity_private_key,
        const vscr_ratchet_private_key_t receiver_long_term_private_key, bool receiver_has_one_time_key,
        const vscr_ratchet_private_key_t receiver_one_time_private_key, vsc_buffer_t *shared_secret) {

    size_t shared_secret_count = receiver_has_one_time_key ? 4 : 3;

        VSCR_ASSERT(vsc_buffer_capacity(shared_secret) >= shared_secret_count * ED25519_DH_LEN);

        vscr_status_t status = vscr_status_SUCCESS;

        int curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), sender_identity_public_key, receiver_long_term_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), sender_ephemeral_public_key, receiver_identity_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        curve_status = curve25519_key_exchange(
                vsc_buffer_unused_bytes(shared_secret), sender_ephemeral_public_key, receiver_long_term_private_key);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto curve_err;
        }

        if (receiver_has_one_time_key) {
            curve_status = curve25519_key_exchange(
                    vsc_buffer_unused_bytes(shared_secret), sender_ephemeral_public_key, receiver_one_time_private_key);
            vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

            if (curve_status != 0) {
                status = vscr_status_ERROR_CURVE25519;
                goto curve_err;
            }
        }

    curve_err:
        return status;
}
