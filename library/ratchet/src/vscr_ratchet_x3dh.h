//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#ifndef VSCR_RATCHET_X3DH_H_INCLUDED
#define VSCR_RATCHET_X3DH_H_INCLUDED

#include "vscr_library.h"
#include "vscr_ratchet_typedefs.h"
#include "vscr_status.h"

#if !VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_initiator_x3dh_secret(const vscr_ratchet_private_key_t sender_identity_private_key,
        const vscr_ratchet_private_key_t sender_ephemeral_private_key,
        const vscr_ratchet_public_key_t receiver_identity_public_key,
        const vscr_ratchet_public_key_t receiver_long_term_public_key, bool receiver_has_one_time_key,
        const vscr_ratchet_public_key_t receiver_one_time_public_key,
        vscr_ratchet_symmetric_key_t shared_key) VSCR_NODISCARD;

VSCR_PUBLIC vscr_status_t
vscr_ratchet_x3dh_compute_responder_x3dh_secret(const vscr_ratchet_public_key_t sender_identity_public_key,
        const vscr_ratchet_public_key_t sender_ephemeral_public_key,
        const vscr_ratchet_private_key_t receiver_identity_private_key,
        const vscr_ratchet_private_key_t receiver_long_term_private_key, bool receiver_has_one_time_key,
        const vscr_ratchet_private_key_t receiver_one_time_private_key,
        vscr_ratchet_symmetric_key_t shared_key) VSCR_NODISCARD;

VSCR_PUBLIC void
vscr_ratchet_x3dh_derive_key(vsc_data_t shared_secret, vscr_ratchet_symmetric_key_t shared_key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_X3DH_H_INCLUDED
//  @end
