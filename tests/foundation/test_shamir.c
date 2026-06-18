//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  (1) Redistributions of source code must retain the above copyright
//  notice, this list of conditions and the following disclaimer.
//
//  (2) Redistributions in binary form must reproduce the above copyright
//  notice, this list of conditions and the following disclaimer in
//  the documentation and/or other materials provided with the
//  distribution.
//
//  (3) Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
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
// --------------------------------------------------------------------------


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_SHAMIR
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_memory.h"
#include "vscf_shamir.h"


// --------------------------------------------------------------------------
//  Helpers.
// --------------------------------------------------------------------------
static const byte test_shamir_SECRET[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1,
        0xf0};

//  Split a secret and return the concatenated shares. Asserts success.
static vsc_buffer_t *
test_shamir_split(vsc_data_t secret, size_t threshold, size_t share_count) {
    vscf_shamir_t *shamir = vscf_shamir_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_shamir_setup_defaults(shamir));

    vsc_buffer_t *shares = vsc_buffer_new_with_capacity(vscf_shamir_shares_len(secret.len, share_count));
    vscf_status_t status = vscf_shamir_split(shamir, secret, threshold, share_count, shares);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_shamir_destroy(&shamir);
    return shares;
}

//  Combine the shares at the given indices (out of `share_count` total) and
//  return the recovery status. On success `out` holds the recovered secret.
static vscf_status_t
test_shamir_combine_indices(
        vsc_data_t all_shares, size_t share_count, const size_t *indices, size_t use_count, vsc_buffer_t *out) {

    const size_t share_size = all_shares.len / share_count;

    vsc_buffer_t *selection = vsc_buffer_new_with_capacity(share_size * use_count);
    for (size_t i = 0; i < use_count; ++i) {
        vsc_buffer_write_data(selection, vsc_data(all_shares.bytes + indices[i] * share_size, share_size));
    }

    vscf_shamir_t *shamir = vscf_shamir_new();
    vscf_status_t status = vscf_shamir_combine(
            shamir, vsc_data(vsc_buffer_bytes(selection), vsc_buffer_len(selection)), use_count, out);

    vscf_shamir_destroy(&shamir);
    vsc_buffer_destroy(&selection);
    return status;
}

//  Output buffer capacity needed to combine `use_count` of `share_count` shares.
static size_t
test_shamir_out_cap(vsc_data_t all_shares, size_t share_count, size_t use_count) {
    const size_t share_size = all_shares.len / share_count;
    return vscf_shamir_recovered_secret_len(share_size * use_count, use_count);
}

//  Recover with the given indices and assert the secret matches the original.
static void
test_shamir_assert_recovers(
        vsc_data_t secret, vsc_data_t all_shares, size_t share_count, const size_t *indices, size_t use_count) {

    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(all_shares, share_count, use_count));
    vscf_status_t status = test_shamir_combine_indices(all_shares, share_count, indices, use_count, recovered);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL(secret.len, vsc_buffer_len(recovered));
    TEST_ASSERT_EQUAL_MEMORY(secret.bytes, vsc_buffer_bytes(recovered), secret.len);

    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
//  Happy path.
// --------------------------------------------------------------------------
void
test__split_combine__2_of_3__every_pair_recovers(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 3);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t pair_01[] = {0, 1};
    const size_t pair_02[] = {0, 2};
    const size_t pair_12[] = {1, 2};
    const size_t reversed[] = {2, 1};

    test_shamir_assert_recovers(secret, shares_data, 3, pair_01, 2);
    test_shamir_assert_recovers(secret, shares_data, 3, pair_02, 2);
    test_shamir_assert_recovers(secret, shares_data, 3, pair_12, 2);
    test_shamir_assert_recovers(secret, shares_data, 3, reversed, 2); // any order

    vsc_buffer_destroy(&shares);
}

void
test__split_combine__5_of_7__recovers(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 5, 7);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t five[] = {6, 4, 2, 1, 0};
    test_shamir_assert_recovers(secret, shares_data, 7, five, 5);
    //  More than the threshold also works.
    const size_t six[] = {0, 1, 2, 3, 4, 5};
    test_shamir_assert_recovers(secret, shares_data, 7, six, 6);

    vsc_buffer_destroy(&shares);
}

void
test__split_combine__k_equals_1__single_share_recovers(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 1, 3);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t one[] = {2};
    test_shamir_assert_recovers(secret, shares_data, 3, one, 1);

    vsc_buffer_destroy(&shares);
}

void
test__split_combine__empty_secret__recovers_empty(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, 0);
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 3);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t pair[] = {0, 2};
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(shares_data, 3, 2) + 1);
    vscf_status_t status = test_shamir_combine_indices(shares_data, 3, pair, 2, recovered);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(recovered));

    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&shares);
}

void
test__split_combine__large_secret__recovers(void) {
    byte big[1000];
    for (size_t i = 0; i < sizeof(big); ++i) {
        big[i] = (byte)(i * 7 + 3);
    }
    vsc_data_t secret = vsc_data(big, sizeof(big));
    vsc_buffer_t *shares = test_shamir_split(secret, 3, 5);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t three[] = {4, 0, 2};
    test_shamir_assert_recovers(secret, shares_data, 5, three, 3);

    vsc_buffer_destroy(&shares);
}

void
test__split_combine__n_equals_255__recovers(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 255);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t pair[] = {254, 0};
    test_shamir_assert_recovers(secret, shares_data, 255, pair, 2);

    vsc_buffer_destroy(&shares);
}


// --------------------------------------------------------------------------
//  Recovery failures (wrong / tampered / insufficient / cross-split).
// --------------------------------------------------------------------------
void
test__combine__insufficient_shares__recovery_fails(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 3, 5); // threshold 3
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    const size_t two[] = {0, 1}; // fewer than threshold
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(shares_data, 5, 2));
    vscf_status_t status = test_shamir_combine_indices(shares_data, 5, two, 2, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_SHAMIR_RECOVERY_FAILED, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(recovered)); // output zeroed/empty on failure

    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&shares);
}

void
test__combine__tampered_ciphertext__recovery_fails(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 3);
    byte *bytes = vsc_buffer_begin(shares);

    //  Flip a byte inside the ciphertext region (offset 68 = header length) of
    //  share 0, the share whose envelope drives decryption.
    bytes[68] ^= 0x01;

    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));
    const size_t pair[] = {0, 1};
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(shares_data, 3, 2));
    vscf_status_t status = test_shamir_combine_indices(shares_data, 3, pair, 2, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_SHAMIR_RECOVERY_FAILED, status);

    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&shares);
}

void
test__combine__tampered_header__bad_arguments(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 3);
    byte *bytes = vsc_buffer_begin(shares);
    const size_t share_size = vsc_buffer_len(shares) / 3;

    //  Flip a commitment byte (offset 32) in share 1 only: the cross-share
    //  header-consistency check must reject it.
    bytes[share_size + 32] ^= 0x01;

    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));
    const size_t pair[] = {0, 1};
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(shares_data, 3, 2));
    vscf_status_t status = test_shamir_combine_indices(shares_data, 3, pair, 2, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, status);

    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&shares);
}

void
test__combine__duplicate_share__bad_arguments(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares = test_shamir_split(secret, 2, 3);
    vsc_data_t shares_data = vsc_data(vsc_buffer_bytes(shares), vsc_buffer_len(shares));

    //  Provide the same share twice -> colliding x-coordinate.
    const size_t dup[] = {1, 1};
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(test_shamir_out_cap(shares_data, 3, 2));
    vscf_status_t status = test_shamir_combine_indices(shares_data, 3, dup, 2, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, status);

    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&shares);
}

void
test__combine__shares_from_different_splits__bad_arguments(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vsc_buffer_t *shares_a = test_shamir_split(secret, 2, 3);
    vsc_buffer_t *shares_b = test_shamir_split(secret, 2, 3);

    const size_t share_size = vsc_buffer_len(shares_a) / 3;

    //  Mix share 0 of split A with share 1 of split B.
    vsc_buffer_t *mixed = vsc_buffer_new_with_capacity(share_size * 2);
    vsc_buffer_write_data(mixed, vsc_data(vsc_buffer_bytes(shares_a), share_size));
    vsc_buffer_write_data(mixed, vsc_data(vsc_buffer_bytes(shares_b) + share_size, share_size));

    vscf_shamir_t *shamir = vscf_shamir_new();
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(vscf_shamir_recovered_secret_len(share_size * 2, 2));
    vscf_status_t status =
            vscf_shamir_combine(shamir, vsc_data(vsc_buffer_bytes(mixed), vsc_buffer_len(mixed)), 2, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, status);

    vscf_shamir_destroy(&shamir);
    vsc_buffer_destroy(&recovered);
    vsc_buffer_destroy(&mixed);
    vsc_buffer_destroy(&shares_a);
    vsc_buffer_destroy(&shares_b);
}

void
test__combine__malformed_short_input__bad_arguments(void) {
    byte junk[10] = {1, 1, 2, 3, 0, 0, 0, 0, 0, 0};
    vscf_shamir_t *shamir = vscf_shamir_new();
    vsc_buffer_t *recovered = vsc_buffer_new_with_capacity(64);
    vscf_status_t status = vscf_shamir_combine(shamir, vsc_data(junk, sizeof(junk)), 1, recovered);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, status);

    vscf_shamir_destroy(&shamir);
    vsc_buffer_destroy(&recovered);
}


// --------------------------------------------------------------------------
//  Argument validation on split.
// --------------------------------------------------------------------------
void
test__split__invalid_threshold__bad_arguments(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vscf_shamir_t *shamir = vscf_shamir_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_shamir_setup_defaults(shamir));

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_shamir_shares_len(secret.len, 3));

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, vscf_shamir_split(shamir, secret, 0, 3, out)); // k = 0
    vsc_buffer_reset(out);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, vscf_shamir_split(shamir, secret, 4, 3, out)); // k > n
    vsc_buffer_reset(out);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_ARGUMENTS, vscf_shamir_split(shamir, secret, 2, 256, out)); // n > 255

    vsc_buffer_destroy(&out);
    vscf_shamir_destroy(&shamir);
}

void
test__split__without_rng__uninitialized(void) {
    vsc_data_t secret = vsc_data(test_shamir_SECRET, sizeof(test_shamir_SECRET));
    vscf_shamir_t *shamir = vscf_shamir_new(); // no setup_defaults / use_random

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(vscf_shamir_shares_len(secret.len, 3));
    vscf_status_t status = vscf_shamir_split(shamir, secret, 2, 3, out);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_UNINITIALIZED, status);

    vsc_buffer_destroy(&out);
    vscf_shamir_destroy(&shamir);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Test runner.
// --------------------------------------------------------------------------
#if !TEST_DEPENDENCIES_AVAILABLE
void
test__nothing__feature_disabled__must_be_ignored(void) {
    TEST_IGNORE_MESSAGE("Feature 'VSCF_SHAMIR' is disabled");
}
#endif

int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__split_combine__2_of_3__every_pair_recovers);
    RUN_TEST(test__split_combine__5_of_7__recovers);
    RUN_TEST(test__split_combine__k_equals_1__single_share_recovers);
    RUN_TEST(test__split_combine__empty_secret__recovers_empty);
    RUN_TEST(test__split_combine__large_secret__recovers);
    RUN_TEST(test__split_combine__n_equals_255__recovers);

    RUN_TEST(test__combine__insufficient_shares__recovery_fails);
    RUN_TEST(test__combine__tampered_ciphertext__recovery_fails);
    RUN_TEST(test__combine__tampered_header__bad_arguments);
    RUN_TEST(test__combine__duplicate_share__bad_arguments);
    RUN_TEST(test__combine__shares_from_different_splits__bad_arguments);
    RUN_TEST(test__combine__malformed_short_input__bad_arguments);

    RUN_TEST(test__split__invalid_threshold__bad_arguments);
    RUN_TEST(test__split__without_rng__uninitialized);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
