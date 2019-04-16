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

#ifndef VIRGIL_CRYPTO_PRIVATEAPI_H
#define VIRGIL_CRYPTO_PRIVATEAPI_H

#include <virgil/crypto/foundation/private/vscf_pkcs8_der_deserializer_defs.h>
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_cipher.h"
#include "vscr_ratchet.h"
#include "vscr_ratchet_sender_chain.h"
#include "vscr_ratchet_receiver_chain_list_node.h"
#include "vscr_ratchet_skipped_message_key_list_node.h"
#include "vscr_ratchet_receiver_chains.h"
#include "vscr_ratchet_skipped_messages.h"
#include "vscr_ratchet_key_utils.h"

struct vscr_ratchet_skipped_messages_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscr_ratchet_skipped_message_key_list_node_t *keys;
};

struct vscr_ratchet_receiver_chains_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscr_ratchet_receiver_chain_list_node_t *chains;
};

struct vscr_ratchet_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;
    //
    //  Dependency to the class 'ratchet cipher'.
    //
    void *cipher;

    void *padding;

    vscr_ratchet_sender_chain_t *sender_chain;

    uint32_t prev_sender_chain_count;

    vscr_ratchet_receiver_chains_t *receiver_chains;

    vscr_ratchet_skipped_messages_t *skipped_messages;

    byte root_key[vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN];
};

struct vscr_ratchet_session_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;

    vscr_ratchet_key_utils_t *key_utils;

    vscr_ratchet_t *ratchet;

    bool is_initiator;

    bool received_first_response;

    byte sender_identity_public_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];

    byte sender_ephemeral_public_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];

    byte receiver_long_term_public_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];

    bool receiver_has_one_time_public_key;

    byte receiver_one_time_public_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];
};

#endif //VIRGIL_CRYPTO_PRIVATEAPI_H
