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

#include "unity.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/ratchet/vscr_memory.h>
#include "msg_channel.h"
#include "test_utils_ratchet.h"

void
deinit_msg(channel_msg_t *msg) {
    if (!msg)
        return;

    vsc_buffer_destroy(&msg->cipher_text);
    vsc_buffer_destroy(&msg->plain_text);
    vscr_dealloc(msg);
}

void
deinit_node(channel_msg_node_t *node) {
    deinit_msg(node->msg);
    vscr_dealloc(node);
}

void
init_channel(msg_channel_t *self, vscf_ctr_drbg_t *rng, double lost_rate, double distribution_factor) {
    self->rng = rng;
    self->msg_count = 0;
    self->lost_rate = lost_rate;

    TEST_ASSERT(distribution_factor >= 0);

    self->distribution_factor = distribution_factor;
}

void
deinit_channel(msg_channel_t *self) {

    if (self->msg_count > 0) {
        channel_msg_node_t *node = self->msg_list;
        for (size_t i = 0; i < self->msg_count; i++) {
            channel_msg_node_t *next = node->next;
            deinit_node(node);
            node = next;
        }
    }
}

bool
push_msg(msg_channel_t *self, vsc_data_t plain_text, vsc_data_t msg, size_t sender) {
    double prob = generate_prob(self->rng);

    if (prob < self->lost_rate) {
        // Lost message
        return false;
    }

    channel_msg_node_t *new_node = vscr_alloc(sizeof(channel_msg_node_t));

    new_node->msg = vscr_alloc(sizeof(channel_msg_t));
    new_node->msg->sender = sender;
    new_node->msg->plain_text = vsc_buffer_new_with_data(plain_text);
    new_node->msg->cipher_text = vsc_buffer_new_with_data(msg);
    new_node->next = NULL;

    channel_msg_node_t *node = self->msg_list;

    if (!node) {
        self->msg_list = new_node;
    } else {
        while (node->next) {
            node = node->next;
        }

        node->next = new_node;
    }

    self->msg_count++;

    return true;
}

bool
has_msg(msg_channel_t *self) {
    return self->msg_count > 0;
}

channel_msg_t *
pop_msg(msg_channel_t *self) {
    size_t number = pick_element_queue(self->rng, self->msg_count, self->distribution_factor);

    channel_msg_node_t **prev = &self->msg_list;
    channel_msg_node_t *node = self->msg_list;
    for (size_t i = 0; i < number; i++) {
        prev = &(node->next);
        node = node->next;
    }

    *prev = node->next;

    self->msg_count--;

    channel_msg_t *res = node->msg;

    node->msg = NULL;

    deinit_node(node);

    return res;
}


#endif