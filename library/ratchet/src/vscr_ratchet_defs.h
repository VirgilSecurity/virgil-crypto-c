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


//  @description
// --------------------------------------------------------------------------
//  Class 'ratchet' types definition.
// --------------------------------------------------------------------------

#ifndef VSCR_RATCHET_DEFS_H_INCLUDED
#define VSCR_RATCHET_DEFS_H_INCLUDED

#include "vscr_library.h"
#include "vscr_atomic.h"
#include "vscr_ratchet_pb_utils.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_keys.h"
#include "vscr_ratchet_key_utils.h"
#include "vscr_ratchet_cipher.h"
#include "vscr_ratchet_sender_chain.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_skipped_messages.h"

#include <virgil/crypto/foundation/private/vscf_message_padding.h>

#if !VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#   include <virgil/crypto/foundation/vscf_round5.h>
#   include <virgil/crypto/foundation/vscf_key_provider.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_key_provider.h>
#   include <VSCFoundation/vscf_impl.h>
#   include <VSCFoundation/vscf_round5.h>
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

//
//  Handle 'ratchet' context.
//
struct vscr_ratchet_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    VSCR_ATOMIC size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;

    vscr_ratchet_key_utils_t *ratchet_key_utils;

    vscr_ratchet_keys_t *ratchet_keys;

    vscf_key_provider_t *key_provider;

    vscf_round5_t *round5;

    bool enable_post_quantum;

    vscr_ratchet_cipher_t *cipher;

    vscf_message_padding_t *padding;

    vscr_ratchet_sender_chain_t *sender_chain;

    uint32_t prev_sender_chain_count;

    vscr_ratchet_receiver_chain_t *receiver_chain;

    vscr_ratchet_skipped_messages_t *skipped_messages;

    vscr_ratchet_symmetric_key_t root_key;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_RATCHET_DEFS_H_INCLUDED
//  @end
