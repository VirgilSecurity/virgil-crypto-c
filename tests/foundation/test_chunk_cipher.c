//  Copyright (C) 2015-2026 Virgil Security, Inc.
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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_CHUNK_CIPHER && VSCF_AES256_GCM && VSCF_FAKE_RANDOM
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_memory.h"
#include "vscf_aes256_gcm.h"
#include "vscf_chunk_cipher.h"
#include "vscf_chunk_cipher_defs.h"
#include "vscf_fake_random.h"
#include "vscf_status.h"

// Must match VSCF_CHUNK_CIPHER_MAX_CHUNK_INDEX in vscf_chunk_cipher.c
static const uint64_t k_max_chunk_index = UINT64_C(1) << 48;

// 32-byte test key for all tests
static const byte k_key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

// plaintext data for tests
static const byte k_short_plaintext[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"

// Creates a chunk cipher with fake random (all 0xAB bytes) and given key
static vscf_chunk_cipher_t *
make_cipher_with_fake_random(void) {
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_chunk_cipher_t *cipher = vscf_chunk_cipher_new();
    vscf_chunk_cipher_take_random(cipher, vscf_fake_random_impl(fake_random));
    vscf_chunk_cipher_set_key(cipher, vsc_data(k_key, sizeof(k_key)));

    return cipher;
}


// --------------------------------------------------------------------------
// Test nonce_len constant
// --------------------------------------------------------------------------
void
test__nonce_len__always__equals_12(void) {

    vscf_chunk_cipher_t *cipher = vscf_chunk_cipher_new();
    TEST_ASSERT_EQUAL(12, vscf_chunk_cipher_nonce_len(cipher));
    vscf_chunk_cipher_destroy(&cipher);
}


// --------------------------------------------------------------------------
// Test round-trip: partial chunk (plaintext < chunk_size)
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__partial_chunk__roundtrip(void) {

    const size_t CHUNK_SIZE = 32;
    vsc_data_t plaintext = vsc_data(k_short_plaintext, sizeof(k_short_plaintext));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));

    // Capture the generated nonce
    vsc_data_t nonce = vscf_chunk_cipher_nonce(enc);
    TEST_ASSERT_EQUAL(12, nonce.len);

    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, nonce.bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));

    vscf_chunk_cipher_destroy(&enc);

    //
    //  Decrypt
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));

    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, recovered);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test round-trip: exactly one full chunk
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__exactly_one_chunk__roundtrip(void) {

    const size_t CHUNK_SIZE = 16;
    byte plaintext_bytes[16];
    memset(plaintext_bytes, 0x42, sizeof(plaintext_bytes));
    vsc_data_t plaintext = vsc_data(plaintext_bytes, sizeof(plaintext_bytes));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    vsc_data_t nonce = vscf_chunk_cipher_nonce(enc);
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, nonce.bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    // One 16-byte data frame (40 bytes) + one empty FIN frame (8+0+16 = 24 bytes) = 64 bytes
    TEST_ASSERT_EQUAL((8 + CHUNK_SIZE + 16) + (8 + 16), vsc_buffer_len(ciphertext));

    //
    //  Decrypt
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, recovered);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test round-trip: multiple chunks
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__multi_chunk__roundtrip(void) {

    const size_t CHUNK_SIZE = 16;
    // 2 full chunks + partial: 2*16 + 7 = 39 bytes
    byte plaintext_bytes[39];
    for (size_t i = 0; i < sizeof(plaintext_bytes); i++) {
        plaintext_bytes[i] = (byte)(i & 0xFF);
    }
    vsc_data_t plaintext = vsc_data(plaintext_bytes, sizeof(plaintext_bytes));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    vsc_data_t nonce = vscf_chunk_cipher_nonce(enc);
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, nonce.bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    // 2 full data frames + 1 FIN frame carrying the 7-byte tail
    // 2 * (16 + 24) + (7 + 24) = 80 + 31 = 111 bytes
    TEST_ASSERT_EQUAL(2 * (CHUNK_SIZE + 24) + (7 + 24), vsc_buffer_len(ciphertext));

    //
    //  Decrypt
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, recovered);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test round-trip: streaming one-byte-at-a-time encryption feed
// --------------------------------------------------------------------------
void
test__process_encryption__one_byte_at_a_time__roundtrip(void) {

    const size_t CHUNK_SIZE = 8;
    byte plaintext_bytes[20];
    for (size_t i = 0; i < sizeof(plaintext_bytes); i++) {
        plaintext_bytes[i] = (byte)(0xA0 + i);
    }
    vsc_data_t plaintext = vsc_data(plaintext_bytes, sizeof(plaintext_bytes));

    //
    //  Encrypt one byte at a time
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    for (size_t i = 0; i < plaintext.len; i++) {
        vsc_data_t one_byte = vsc_data(plaintext.bytes + i, 1);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, one_byte, ciphertext));
    }
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    //
    //  Decrypt
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, recovered);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test: tampered ciphertext fails authentication
// --------------------------------------------------------------------------
void
test__decrypt__tampered_ciphertext__auth_fails(void) {

    const size_t CHUNK_SIZE = 16;
    byte plaintext_bytes[10];
    memset(plaintext_bytes, 0x11, sizeof(plaintext_bytes));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, sizeof(plaintext_bytes)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_chunk_cipher_process_encryption(enc, vsc_data(plaintext_bytes, sizeof(plaintext_bytes)), ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    // Tamper with the ciphertext byte (byte 8 is first ciphertext byte, after 8-byte counter)
    vsc_buffer_begin(ciphertext)[8] ^= 0xFF;

    //
    //  Decrypt — must fail
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test: wrong counter in frame is detected
// --------------------------------------------------------------------------
void
test__decrypt__wrong_frame_counter__fails(void) {

    const size_t CHUNK_SIZE = 16;
    // Use 10 bytes (< CHUNK_SIZE) so the single frame (10+24=34 bytes) is smaller
    // than full_frame_size (16+24=40), which keeps it in pending until finish_decryption.
    byte plaintext_bytes[10];
    memset(plaintext_bytes, 0x22, sizeof(plaintext_bytes));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, sizeof(plaintext_bytes)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_chunk_cipher_process_encryption(enc, vsc_data(plaintext_bytes, sizeof(plaintext_bytes)), ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    // The frame counter (bytes 0-7) is 0x00...00 for frame 0.
    // Tamper the counter to 0x01 so it no longer matches chunk_index=0.
    vsc_buffer_begin(ciphertext)[0] = 0x01;

    //
    //  Decrypt — must fail due to counter mismatch
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    // Frame (34 bytes) is smaller than full_frame_size (40 bytes) so it stays in pending
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));

    // finish_decryption flushes the pending frame and must detect the counter mismatch
    const vscf_status_t status = vscf_chunk_cipher_finish_decryption(dec, recovered);
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, status);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test: nonce generated by start_encryption is exactly 12 bytes
// --------------------------------------------------------------------------
void
test__start_encryption__nonce__has_12_bytes(void) {

    vscf_chunk_cipher_t *cipher = make_cipher_with_fake_random();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(cipher));
    TEST_ASSERT_EQUAL(12, vscf_chunk_cipher_nonce(cipher).len);
    vscf_chunk_cipher_destroy(&cipher);
}


// --------------------------------------------------------------------------
// Test: nonce() after encryption uses the fake random fill byte (0xAB)
// --------------------------------------------------------------------------
void
test__start_encryption__nonce__filled_by_random(void) {

    vscf_chunk_cipher_t *cipher = make_cipher_with_fake_random();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(cipher));

    vsc_data_t nonce = vscf_chunk_cipher_nonce(cipher);
    TEST_ASSERT_EQUAL(12, nonce.len);

    // With fake_random setup_source_byte(0xAB), all nonce bytes should be 0xAB
    for (size_t i = 0; i < nonce.len; i++) {
        TEST_ASSERT_EQUAL_HEX8(0xAB, nonce.bytes[i]);
    }

    vscf_chunk_cipher_destroy(&cipher);
}


// --------------------------------------------------------------------------
// Test: encrypt/decrypt with default chunk size (65536)
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__default_chunk_size__roundtrip(void) {

    // Small plaintext; default chunk_size = 65536 so it's a single partial chunk
    byte plaintext_bytes[100];
    for (size_t i = 0; i < sizeof(plaintext_bytes); i++) {
        plaintext_bytes[i] = (byte)(i & 0xFF);
    }
    vsc_data_t plaintext = vsc_data(plaintext_bytes, sizeof(plaintext_bytes));

    //
    //  Encrypt (default chunk_size)
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    //
    //  Decrypt (must use same default chunk_size)
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, recovered);

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test: truncated stream (FIN frame stripped) is rejected
// --------------------------------------------------------------------------
void
test__decrypt__truncated_stream__fails(void) {

    const size_t CHUNK_SIZE = 16;
    // 2 full chunks — data_len is an exact multiple so finish emits an empty FIN frame
    byte plaintext_bytes[32];
    memset(plaintext_bytes, 0x33, sizeof(plaintext_bytes));

    //
    //  Encrypt
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, sizeof(plaintext_bytes)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_chunk_cipher_process_encryption(enc, vsc_data(plaintext_bytes, sizeof(plaintext_bytes)), ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    // Ciphertext: 2 data frames (40 each) + 1 empty FIN frame (24) = 104 bytes
    TEST_ASSERT_EQUAL(2 * (CHUNK_SIZE + 24) + 24, vsc_buffer_len(ciphertext));

    // Strip the 24-byte FIN frame to simulate a truncated stream
    const size_t truncated_len = vsc_buffer_len(ciphertext) - 24;

    //
    //  Decrypt the truncated stream — must fail because FIN frame is absent
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, truncated_len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec,
                                                   vsc_data(vsc_buffer_bytes(ciphertext), truncated_len), recovered));
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Test: mismatched chunk_size is detected via frame-0 AAD
// --------------------------------------------------------------------------
void
test__decrypt__tampered_chunk_size__auth_fails(void) {

    const size_t ENC_CHUNK_SIZE = 16;
    const size_t DEC_CHUNK_SIZE = 32;
    byte plaintext_bytes[10];
    memset(plaintext_bytes, 0x44, sizeof(plaintext_bytes));

    //
    //  Encrypt with chunk_size=16
    //
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, ENC_CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memcpy(nonce_bytes, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);

    vsc_buffer_t *ciphertext =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, sizeof(plaintext_bytes)));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_chunk_cipher_process_encryption(enc, vsc_data(plaintext_bytes, sizeof(plaintext_bytes)), ciphertext));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ciphertext));
    vscf_chunk_cipher_destroy(&enc);

    //
    //  Decrypt with tampered chunk_size=32 — must fail: frame 0 AAD includes chunk_size
    //
    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, DEC_CHUNK_SIZE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));
    vsc_buffer_t *recovered =
            vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, vsc_buffer_len(ciphertext)));
    // FIN frame (34 bytes) < full_frame_size with chunk_size=32 (56), so stays in pending
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_process_decryption(dec, vsc_buffer_data(ciphertext), recovered));
    TEST_ASSERT_NOT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_decryption(dec, recovered));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ciphertext);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
// Regression: chunk_index must be a fixed 64-bit counter on every platform.
// A size_t counter wraps after 2^32 frames on 32-bit targets (wasm32, ARM32),
// reusing frame 0's AES-GCM nonce under the same key.
// --------------------------------------------------------------------------
void
test__chunk_index__type__is_64_bit(void) {

    vscf_chunk_cipher_t *cipher = vscf_chunk_cipher_new();
    TEST_ASSERT_EQUAL(8, sizeof(cipher->chunk_index));
    vscf_chunk_cipher_destroy(&cipher);
}


// --------------------------------------------------------------------------
// Regression: the frame counter is capped so a per-frame nonce can never
// repeat — encryption fails closed once the cap is reached.
// --------------------------------------------------------------------------
void
test__encrypt__chunk_counter_at_limit__fails_with_limit_error(void) {

    const size_t CHUNK_SIZE = 16;
    byte plaintext_bytes[16];
    memset(plaintext_bytes, 0x55, sizeof(plaintext_bytes));
    vsc_data_t plaintext = vsc_data(plaintext_bytes, sizeof(plaintext_bytes));

    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, CHUNK_SIZE);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));

    // Simulate a stream that already produced all-but-one allowed frames.
    enc->chunk_index = k_max_chunk_index - 1;

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(3 * vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));

    // The last allowed frame index still encrypts.
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, out));

    // Counter reached the cap: the next frame is refused...
    TEST_ASSERT_EQUAL(
            vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED, vscf_chunk_cipher_process_encryption(enc, plaintext, out));

    // ...and so is the FIN frame.
    TEST_ASSERT_EQUAL(vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED, vscf_chunk_cipher_finish_encryption(enc, out));

    vscf_chunk_cipher_destroy(&enc);
    vsc_buffer_destroy(&out);
}


// --------------------------------------------------------------------------
// Regression: decryption refuses a frame whose counter is at the cap,
// even when it matches the expected sequence.
// --------------------------------------------------------------------------
void
test__decrypt__frame_counter_at_limit__fails_with_limit_error(void) {

    const size_t CHUNK_SIZE = 16;
    byte nonce_bytes[vscf_aes256_gcm_NONCE_LEN];
    memset(nonce_bytes, 0xAB, sizeof(nonce_bytes));

    vscf_chunk_cipher_t *dec = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(dec, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(dec, vsc_data(nonce_bytes, vscf_aes256_gcm_NONCE_LEN));
    vscf_chunk_cipher_set_chunk_size(dec, CHUNK_SIZE);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_decryption(dec));

    dec->chunk_index = k_max_chunk_index;

    // Full frame: counter_le64 == k_max_chunk_index, ciphertext and tag are irrelevant —
    // the counter cap must be enforced before tag verification is even attempted.
    byte frame[16 + 8 + 16] = {0};
    frame[6] = 0x01; // little-endian encoding of 2^48

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, sizeof(frame)));
    TEST_ASSERT_EQUAL(vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED,
            vscf_chunk_cipher_process_decryption(dec, vsc_data(frame, sizeof(frame)), out));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&out);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__nonce_len__always__equals_12);
    RUN_TEST(test__start_encryption__nonce__has_12_bytes);
    RUN_TEST(test__start_encryption__nonce__filled_by_random);
    RUN_TEST(test__encrypt_decrypt__partial_chunk__roundtrip);
    RUN_TEST(test__encrypt_decrypt__exactly_one_chunk__roundtrip);
    RUN_TEST(test__encrypt_decrypt__multi_chunk__roundtrip);
    RUN_TEST(test__process_encryption__one_byte_at_a_time__roundtrip);
    RUN_TEST(test__encrypt_decrypt__default_chunk_size__roundtrip);
    RUN_TEST(test__decrypt__tampered_ciphertext__auth_fails);
    RUN_TEST(test__decrypt__wrong_frame_counter__fails);
    RUN_TEST(test__decrypt__truncated_stream__fails);
    RUN_TEST(test__decrypt__tampered_chunk_size__auth_fails);
    RUN_TEST(test__chunk_index__type__is_64_bit);
    RUN_TEST(test__encrypt__chunk_counter_at_limit__fails_with_limit_error);
    RUN_TEST(test__decrypt__frame_counter_at_limit__fails_with_limit_error);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
