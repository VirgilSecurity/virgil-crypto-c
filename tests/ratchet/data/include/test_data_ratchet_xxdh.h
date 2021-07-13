//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#ifndef VIRGIL_CRYPTO_TEST_DATA_RATCHET_XXDH_H
#define VIRGIL_CRYPTO_TEST_DATA_RATCHET_XXDH_H

#include "vsc_data.h"

extern const vsc_data_t test_data_ratchet_xxdh_random;
extern const vsc_data_t test_data_ratchet_xxdh_sender_identity_private_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_sender_identity_public_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_identity_private_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_identity_public_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_long_term_private_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_long_term_public_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_one_time_private_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_receiver_one_time_public_key_first;

extern const vsc_data_t test_data_ratchet_xxdh_sender_ephemeral_public_key_first;
extern const vsc_data_t test_data_ratchet_xxdh_shared_secret_first;
extern const vsc_data_t test_data_ratchet_xxdh_shared_secret_weak_first;

extern const vsc_data_t test_data_ratchet_xxdh_ephemeral_public_key_pqc_first;
extern const vsc_data_t test_data_ratchet_xxdh_encapsulated_key1;
extern const vsc_data_t test_data_ratchet_xxdh_encapsulated_key2;
extern const vsc_data_t test_data_ratchet_xxdh_encapsulated_key3;
extern const vsc_data_t test_data_ratchet_xxdh_decapsulated_keys_signature;
extern const vsc_data_t test_data_ratchet_xxdh_decapsulated_keys_signature_weak;

extern const vsc_data_t test_data_ratchet_xxdh_shared_secret_pqc;
extern const vsc_data_t test_data_ratchet_xxdh_shared_secret_weak_pqc;

#endif //VIRGIL_CRYPTO_TEST_DATA_RATCHET_XXDH_H
