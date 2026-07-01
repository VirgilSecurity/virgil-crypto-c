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


// ==========================================================================
// Seek API: encrypt_at / decrypt_at / chunk_count (random-access + parallel)
// ==========================================================================

// Build a seek-mode cipher: key + explicit nonce + chunk_size, left in INITIAL state
// (no start_encryption/start_decryption — the seek methods run outside the state machine).
static vscf_chunk_cipher_t *
make_seek_cipher(size_t chunk_size, vsc_data_t nonce) {
    vscf_chunk_cipher_t *c = vscf_chunk_cipher_new();
    vscf_chunk_cipher_set_key(c, vsc_data(k_key, sizeof(k_key)));
    vscf_chunk_cipher_set_nonce(c, nonce);
    vscf_chunk_cipher_set_chunk_size(c, chunk_size);
    return c;
}

// Encrypt `plaintext` via the sequential path; return the ciphertext buffer and copy out the nonce.
static vsc_buffer_t *
seq_encrypt(size_t chunk_size, vsc_data_t plaintext, byte nonce_out[vscf_aes256_gcm_NONCE_LEN]) {
    vscf_chunk_cipher_t *enc = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(enc, chunk_size);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(enc));
    memcpy(nonce_out, vscf_chunk_cipher_nonce(enc).bytes, vscf_aes256_gcm_NONCE_LEN);
    vsc_buffer_t *ct = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(enc, plaintext.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_process_encryption(enc, plaintext, ct));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_finish_encryption(enc, ct));
    vscf_chunk_cipher_destroy(&enc);
    return ct;
}

void
test__chunk_count__various_lengths__matches_floor_plus_one(void) {
    const size_t C = 32;
    vscf_chunk_cipher_t *c = make_cipher_with_fake_random();
    vscf_chunk_cipher_set_chunk_size(c, C);
    TEST_ASSERT_EQUAL(1, vscf_chunk_cipher_chunk_count(c, 0));
    TEST_ASSERT_EQUAL(1, vscf_chunk_cipher_chunk_count(c, C - 1));
    TEST_ASSERT_EQUAL(2, vscf_chunk_cipher_chunk_count(c, C)); // exact multiple -> trailing empty FIN frame
    TEST_ASSERT_EQUAL(3, vscf_chunk_cipher_chunk_count(c, 2 * C + 1));
    vscf_chunk_cipher_destroy(&c);
}

// encrypt every index via encrypt_at (reusing one INITIAL-state instance) and assert the
// concatenated frames are byte-identical to the sequential process/finish output.
static void
check_parallel_equivalence(size_t C, size_t N) {
    byte *pt = (byte *)vscf_alloc(N > 0 ? N : 1);
    for (size_t i = 0; i < N; i++) {
        pt[i] = (byte)(i & 0xFF);
    }
    vsc_data_t plaintext = vsc_data(pt, N);

    byte nonce[vscf_aes256_gcm_NONCE_LEN];
    vsc_buffer_t *seq_ct = seq_encrypt(C, plaintext, nonce);

    vscf_chunk_cipher_t *seek = make_seek_cipher(C, vsc_data(nonce, sizeof(nonce)));
    const size_t n = vscf_chunk_cipher_chunk_count(seek, N);
    vsc_buffer_t *par_ct = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(seek, N));

    for (size_t i = 0; i < n; i++) {
        const size_t off = i * C;
        const size_t len = (off >= N) ? 0 : ((off + C <= N) ? C : (N - off));
        vsc_data_t slice = vsc_data(pt + (off < N ? off : N), len);
        const bool is_last = (i == n - 1);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_encrypt_at(seek, (uint64_t)i, is_last, slice, par_ct));
    }

    TEST_ASSERT_EQUAL(vsc_buffer_len(seq_ct), vsc_buffer_len(par_ct));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(seq_ct), vsc_buffer_bytes(par_ct), vsc_buffer_len(seq_ct));

    vscf_chunk_cipher_destroy(&seek);
    vsc_buffer_destroy(&seq_ct);
    vsc_buffer_destroy(&par_ct);
    vscf_dealloc(pt);
}

void
test__encrypt_at__parallel_non_multiple__matches_sequential(void) {
    check_parallel_equivalence(16, 2 * 16 + 5);
}

void
test__encrypt_at__parallel_exact_multiple__matches_sequential(void) {
    // The break point: sequential emits 3 frames (2 full + empty FIN); a naive caller marking
    // index 1 as last would NOT match. encrypt_at must include the empty index-2 is_last frame.
    check_parallel_equivalence(16, 2 * 16);
}

void
test__decrypt_at__random_access__recovers_any_chunk(void) {
    const size_t C = 16;
    const size_t N = 2 * C; // 3 frames: idx0/idx1 full, idx2 empty FIN
    byte pt[2 * 16];
    for (size_t i = 0; i < N; i++) {
        pt[i] = (byte)(i & 0xFF);
    }
    byte nonce[vscf_aes256_gcm_NONCE_LEN];
    vsc_buffer_t *ct = seq_encrypt(C, vsc_data(pt, N), nonce);

    const size_t full_frame = C + 8 + vscf_aes256_gcm_AUTH_TAG_LEN;
    const byte *ctb = vsc_buffer_bytes(ct);
    vscf_chunk_cipher_t *dec = make_seek_cipher(C, vsc_data(nonce, sizeof(nonce)));

    // Middle chunk first, without decrypting chunk 0.
    vsc_buffer_t *out1 = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, full_frame));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_chunk_cipher_decrypt_at(dec, 1, false, vsc_data(ctb + full_frame, full_frame), out1));
    TEST_ASSERT_EQUAL_MEMORY(pt + C, vsc_buffer_bytes(out1), C);

    // Chunk 0.
    vsc_buffer_t *out0 = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, full_frame));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_decrypt_at(dec, 0, false, vsc_data(ctb, full_frame), out0));
    TEST_ASSERT_EQUAL_MEMORY(pt, vsc_buffer_bytes(out0), C);

    // Trailing empty FIN frame at index 2.
    const size_t last_off = 2 * full_frame;
    const size_t last_len = vsc_buffer_len(ct) - last_off;
    vsc_buffer_t *out2 = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, last_len));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_chunk_cipher_decrypt_at(dec, 2, true, vsc_data(ctb + last_off, last_len), out2));
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out2));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ct);
    vsc_buffer_destroy(&out0);
    vsc_buffer_destroy(&out1);
    vsc_buffer_destroy(&out2);
}

void
test__decrypt_at__wrong_index__fails_closed(void) {
    const size_t C = 16;
    const size_t N = 2 * C;
    byte pt[2 * 16];
    memset(pt, 0x11, sizeof(pt));
    byte nonce[vscf_aes256_gcm_NONCE_LEN];
    vsc_buffer_t *ct = seq_encrypt(C, vsc_data(pt, N), nonce);

    const size_t full_frame = C + 8 + vscf_aes256_gcm_AUTH_TAG_LEN;
    const byte *ctb = vsc_buffer_bytes(ct);
    vscf_chunk_cipher_t *dec = make_seek_cipher(C, vsc_data(nonce, sizeof(nonce)));
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, full_frame));

    // Present frame-of-index-1 to decrypt_at(expected_index=0): counter mismatch, never wrong plaintext.
    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ENCRYPTED_DATA,
            vscf_chunk_cipher_decrypt_at(dec, 0, false, vsc_data(ctb + full_frame, full_frame), out));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ct);
    vsc_buffer_destroy(&out);
}

void
test__decrypt_at__wrong_is_last__auth_fails(void) {
    const size_t C = 16;
    const size_t N = 2 * C;
    byte pt[2 * 16];
    memset(pt, 0x22, sizeof(pt));
    byte nonce[vscf_aes256_gcm_NONCE_LEN];
    vsc_buffer_t *ct = seq_encrypt(C, vsc_data(pt, N), nonce);

    const size_t full_frame = C + 8 + vscf_aes256_gcm_AUTH_TAG_LEN;
    const byte *ctb = vsc_buffer_bytes(ct);
    vscf_chunk_cipher_t *dec = make_seek_cipher(C, vsc_data(nonce, sizeof(nonce)));
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chunk_cipher_decryption_out_len(dec, full_frame));

    // Frame 0 is NOT last; passing is_last=true flips the FIN AAD -> tag mismatch.
    TEST_ASSERT_EQUAL(
            vscf_status_ERROR_AUTH_FAILED, vscf_chunk_cipher_decrypt_at(dec, 0, true, vsc_data(ctb, full_frame), out));

    vscf_chunk_cipher_destroy(&dec);
    vsc_buffer_destroy(&ct);
    vsc_buffer_destroy(&out);
}

void
test__encrypt_at__index_at_limit__fails_with_limit_error(void) {
    const byte nonce[vscf_aes256_gcm_NONCE_LEN] = {0};
    vscf_chunk_cipher_t *c = make_seek_cipher(16, vsc_data(nonce, sizeof(nonce)));
    vsc_data_t pt = vsc_data(k_short_plaintext, sizeof(k_short_plaintext));
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_chunk_cipher_encryption_out_len(c, pt.len));
    TEST_ASSERT_EQUAL(vscf_status_ERROR_CHUNK_COUNTER_LIMIT_REACHED,
            vscf_chunk_cipher_encrypt_at(c, k_max_chunk_index, false, pt, out));
    vscf_chunk_cipher_destroy(&c);
    vsc_buffer_destroy(&out);
}

void
test__encrypt_at__missing_preconditions__return_status_not_crash(void) {
    const byte nonce[vscf_aes256_gcm_NONCE_LEN] = {0};
    vsc_data_t pt = vsc_data(k_short_plaintext, sizeof(k_short_plaintext));

    // No key set.
    {
        vscf_chunk_cipher_t *c = vscf_chunk_cipher_new();
        vscf_chunk_cipher_set_nonce(c, vsc_data(nonce, sizeof(nonce)));
        vscf_chunk_cipher_set_chunk_size(c, 16);
        vsc_buffer_t *out = vsc_buffer_new_with_capacity(1024);
        TEST_ASSERT_EQUAL(vscf_status_ERROR_UNINITIALIZED, vscf_chunk_cipher_encrypt_at(c, 0, true, pt, out));
        vscf_chunk_cipher_destroy(&c);
        vsc_buffer_destroy(&out);
    }

    // No nonce set (chunk_size is always defaulted by init_ctx, so it can't be the missing one).
    {
        vscf_chunk_cipher_t *c = vscf_chunk_cipher_new();
        vscf_chunk_cipher_set_key(c, vsc_data(k_key, sizeof(k_key)));
        vscf_chunk_cipher_set_chunk_size(c, 16);
        vsc_buffer_t *out = vsc_buffer_new_with_capacity(1024);
        TEST_ASSERT_EQUAL(vscf_status_ERROR_UNINITIALIZED, vscf_chunk_cipher_encrypt_at(c, 0, true, pt, out));
        vscf_chunk_cipher_destroy(&c);
        vsc_buffer_destroy(&out);
    }

    // Sequential session active (state != INITIAL): must reject, not corrupt the session.
    {
        vscf_chunk_cipher_t *c = make_cipher_with_fake_random();
        vscf_chunk_cipher_set_chunk_size(c, 16);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chunk_cipher_start_encryption(c));
        vsc_buffer_t *out = vsc_buffer_new_with_capacity(1024);
        TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, vscf_chunk_cipher_encrypt_at(c, 0, true, pt, out));
        vscf_chunk_cipher_destroy(&c);
        vsc_buffer_destroy(&out);
    }
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
    RUN_TEST(test__chunk_count__various_lengths__matches_floor_plus_one);
    RUN_TEST(test__encrypt_at__parallel_non_multiple__matches_sequential);
    RUN_TEST(test__encrypt_at__parallel_exact_multiple__matches_sequential);
    RUN_TEST(test__decrypt_at__random_access__recovers_any_chunk);
    RUN_TEST(test__decrypt_at__wrong_index__fails_closed);
    RUN_TEST(test__decrypt_at__wrong_is_last__auth_fails);
    RUN_TEST(test__encrypt_at__index_at_limit__fails_with_limit_error);
    RUN_TEST(test__encrypt_at__missing_preconditions__return_status_not_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
