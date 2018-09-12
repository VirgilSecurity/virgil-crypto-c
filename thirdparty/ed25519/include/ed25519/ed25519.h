/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of extension to mbed TLS (https://tls.mbed.org)
 */

#ifndef ED25519_H_INCLUDED
#define ED25519_H_INCLUDED

#include <stddef.h>

#define ED25519_KEY_LEN 32
#define ED25519_SIG_LEN 64
#define ED25519_DH_LEN  32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive public key from the private key.
 *
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param secret_key - Curve25519 secret key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int curve25519_get_pubkey(
        unsigned char public_key[ED25519_KEY_LEN], const unsigned char secret_key[ED25519_KEY_LEN]);


/**
 * @brief Compute shared secret based on the Curve25519 montgomery curve
 *
 * @param shared_key - computed shared secret (unsigned binary data, low endian, 32 byte)
 * @param public_key - Curve25519 public key from other party (unsigned binary data, low endian, 32 byte)
 * @param secret_key - Curve25519 secret key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int curve25519_key_exchange(
        unsigned char shared_key[ED25519_DH_LEN],
        const unsigned char public_key[ED25519_KEY_LEN],
        const unsigned char secret_key[ED25519_KEY_LEN]);

/**
 * @brief Create signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param secret_key - Curve25519 secret key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be signed
 * @param msg_len - message length
 * @return 0 on success
 */
int curve25519_sign(
        unsigned char signature[ED25519_SIG_LEN],
        const unsigned char secret_key[ED25519_KEY_LEN],
        const unsigned char* msg, size_t msg_len);


/**
 * @brief Verify signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be verified
 * @param msg_len - message length
 * @return 0 on success
 */
int curve25519_verify(
        const unsigned char signature[ED25519_SIG_LEN],
        const unsigned char public_key[ED25519_KEY_LEN],
        const unsigned char* msg, size_t msg_len);

/**
 * @brief Derive public key from the private key.
 *
 * @param public_key - Ed25519 public key (unsigned binary data, low endian, 32 byte)
 * @param secret_key - Ed25519 secret key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int ed25519_get_pubkey(
        unsigned char public_key[ED25519_KEY_LEN], const unsigned char secret_key[ED25519_KEY_LEN]);

/**
 * @brief Create signature based on the Ed25519 edwards curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param secret_key - Ed25519 secret key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be signed
 * @param msg_len - message length
 * @return 0 on success
 */
int ed25519_sign(
        unsigned char signature[ED25519_SIG_LEN],
        const unsigned char secret_key[ED25519_KEY_LEN],
        const unsigned char* msg, size_t msg_len);


/**
 * @brief Verify signature based on the Ed25519 edwards curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param public_key - Ed25519 public key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be verified
 * @param msg_len - message length
 * @return 0 on success
 */
int ed25519_verify(
        const unsigned char signature[ED25519_SIG_LEN],
        const unsigned char public_key[ED25519_KEY_LEN],
        const unsigned char* msg, size_t msg_len);

/**
 * @brief Convert Ed25519 public key to the birationally equivalent Curve25519 public key.
 * @param curve_public_key Curve25519 public key.
 * @param ed_public_key Ed25519 public key.
 * @return 0 if success, non zero - otherwise.
 */
int ed25519_pubkey_to_curve25519(
        unsigned char curve_public_key[ED25519_KEY_LEN],
        const unsigned char ed_public_key[ED25519_KEY_LEN]);

/**
 * @brief Convert Ed25519 scret key to the equivalent Curve25519 secret key.
 * @param curve_secret_key Curve25519 secret key.
 * @param ed_secret_key Ed25519 secret key.
 * @return 0 if success, non zero - otherwise.
 */
int ed25519_key_to_curve25519(
        unsigned char curve_secret_key[ED25519_KEY_LEN],
        const unsigned char ed_secret_key[ED25519_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_H_INCLUDED */
