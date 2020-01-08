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

#ifndef VIRGIL_CRYPTO_MSG_CHANNEL_H
#define VIRGIL_CRYPTO_MSG_CHANNEL_H


#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

typedef struct channel_msg {
    vsc_buffer_t *plain_text;
    vsc_buffer_t *cipher_text;
    size_t sender;
} channel_msg_t;

typedef struct channel_msg_node channel_msg_node_t;

struct channel_msg_node {
    channel_msg_t *msg;
    channel_msg_node_t *next;
};

typedef struct msg_channel {
    vscf_ctr_drbg_t *rng;
    double lost_rate;
    double distribution_factor;
    channel_msg_node_t *msg_list;
    size_t msg_count;
} msg_channel_t;

void deinit_msg(channel_msg_t *msg);
void deinit_node(channel_msg_node_t *node);
void init_channel(msg_channel_t *self, vscf_ctr_drbg_t *rng, double lost_rate, double distribution_factor);
void deinit_channel(msg_channel_t *self);
bool push_msg(msg_channel_t *self, vsc_data_t plain_text, vsc_data_t msg, size_t sender);
bool has_msg(msg_channel_t *self);
channel_msg_t *pop_msg(msg_channel_t *self);

#endif //VIRGIL_CRYPTO_MSG_CHANNEL_H
