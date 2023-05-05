//  Copyright (C) 2015-2022 Virgil Security, Inc.
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

#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <vscr_ratchet_receiver_chain.h>
#include <vscr_ratchet_sender_chain.h>
#include <vscr_ratchet.h>
#include "virgil/crypto/common/vsc_buffer.h"
#include "virgil/crypto/foundation/vscf_ctr_drbg.h"
#include "vscr_ratchet_session.h"
#include "vscr_ratchet_typedefs.h"
#include "vscr_ratchet_message_key.h"
#include "vscr_ratchet_skipped_messages_root_node.h"

size_t pick_element_uniform(vscf_ctr_drbg_t *rng, size_t size);
size_t pick_element_queue(vscf_ctr_drbg_t *rng, size_t size, double distribution_factor);
size_t generate_number(vscf_ctr_drbg_t *rng, size_t min, size_t max);
double generate_prob(vscf_ctr_drbg_t *rng);
size_t generate_size(vscf_ctr_drbg_t *rng);
void generate_random_data(vscf_ctr_drbg_t *rng, vsc_buffer_t **buffer);
void generate_permutation(vscf_ctr_drbg_t *rng, size_t n, size_t *buffer);
void generate_PKCS8_ed_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub);
void generate_PKCS8_curve_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub);
void generate_random_participant_id(vscf_ctr_drbg_t *rng, vsc_buffer_t **id);
vscf_impl_t *
generate_identity_private_key(vscf_key_provider_t *key_provider, bool enable_pqc);
vscf_impl_t *
generate_ephemeral_private_key(vscf_key_provider_t *key_provider, bool enable_pqc);
void
generate_falcon_keypair(vscf_ctr_drbg_t *rng, vscf_impl_t **priv, vscf_impl_t **pub);
void
generate_round5_keypair(vscf_ctr_drbg_t *rng, vscf_impl_t **priv, vscf_impl_t **pub);
void generate_raw_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub, bool curve25519);
void generate_random_key_id(vscf_ctr_drbg_t *rng, vscr_ratchet_key_id_t id);
void initialize(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool enable_one_time, bool enable_pqc, bool should_restore);
void encrypt_decrypt__100_plain_texts_random_order(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob);
void encrypt_decrypt__100_plain_texts_random_order_with_producers(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool should_restore);
void restore_session(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session);

vscr_ratchet_t *generate_full_ratchet(vscf_ctr_drbg_t *rng);
vscf_impl_t *generate_public_key(vscf_ctr_drbg_t *rng);
void
generate_random_c(vscf_ctr_drbg_t *rng, byte *data, size_t len);
vscr_ratchet_session_t *generate_full_session(vscf_ctr_drbg_t *rng);
vsc_buffer_t *
generate_random_buff(vscf_ctr_drbg_t *rng, size_t len);
vscr_ratchet_receiver_chain_t *generate_full_receiver_chain(vscf_ctr_drbg_t *rng);
vscr_ratchet_sender_chain_t *generate_full_sender_chain(vscf_ctr_drbg_t *rng);
vscr_ratchet_message_key_t *
generate_full_message_key(vscf_ctr_drbg_t *rng);
void
generate_full_chain_key_s(vscf_ctr_drbg_t *rng, vscr_ratchet_chain_key_t *chain_key);
vscr_ratchet_chain_key_t *
generate_full_chain_key(vscf_ctr_drbg_t *rng);
vscr_ratchet_skipped_messages_root_node_t *
generate_full_root_node(vscf_ctr_drbg_t *rng, bool max);

#endif //VIRGIL_CRYPTO_TEST_UTILS_RATCHET_H
