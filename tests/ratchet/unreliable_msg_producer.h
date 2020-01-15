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

#ifndef VIRGIL_CRYPTO_UNRELIABLE_MSG_PRODUCER_H
#define VIRGIL_CRYPTO_UNRELIABLE_MSG_PRODUCER_H

#include "virgil/crypto/foundation/vscf_ctr_drbg.h"
#include "vscr_ratchet_session.h"
#include "vscr_ratchet_message.h"

typedef struct out_of_order_msg {
    vscr_ratchet_message_t *cipher_text;
    vsc_buffer_t *plain_text;
    size_t index;
} out_of_order_msg_t;

typedef struct out_of_order_msg_node out_of_order_msg_node_t;

struct out_of_order_msg_node {
    out_of_order_msg_t *msg;
    out_of_order_msg_node_t *next;
};

typedef struct unreliable_msg_producer {
    vscf_ctr_drbg_t *rng;
    vscr_ratchet_session_t **session;
    out_of_order_msg_node_t *skipped_msgs_list;
    size_t produced_count;
    float lost_rate;
    float out_of_order_rate;
    bool sent_first_response;
} unreliable_msg_producer_t;

void
init_producer(
        unreliable_msg_producer_t *producer, vscr_ratchet_session_t **session, float lost_rate, float out_of_order_rate);

void
deinit_producer(unreliable_msg_producer_t *producer);

void produce_msg(unreliable_msg_producer_t *producer, vsc_buffer_t **plain_text, vscr_ratchet_message_t **msg, bool should_restore);

#endif // VIRGIL_CRYPTO_UNRELIABLE_MSG_PRODUCER_H
