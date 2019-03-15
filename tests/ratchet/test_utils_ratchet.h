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

#ifndef VIRGIL_CRYPTO_TEST_UTILS_RATCHET_H
#define VIRGIL_CRYPTO_TEST_UTILS_RATCHET_H

#include "virgil/crypto/common/vsc_buffer.h"
#include "vscr_ratchet_session.h"

void generate_random_data(vsc_buffer_t **buffer);
void generate_PKCS8_keypair(vsc_buffer_t **priv, vsc_buffer_t **pub);
void generate_raw_keypair(vsc_buffer_t **priv, vsc_buffer_t **pub);
void initialize(vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool enable_one_time, bool should_restore);
void encrypt_decrypt__100_plain_texts_random_order(vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob);
void encrypt_decrypt__100_plain_texts_random_order_with_producers(vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool should_restore);
void restore_session(vscr_ratchet_session_t **session);

#endif //VIRGIL_CRYPTO_TEST_UTILS_RATCHET_H
