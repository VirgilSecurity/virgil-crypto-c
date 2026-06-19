/*
 * Low level API for Daan Sprenkels' Shamir secret sharing library
 * Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>
 *
 * Usage of this API is hazardous and is only reserved for beings with a
 * good understanding of the Shamir secret sharing scheme and who know how
 * crypto code is implemented. If you are unsure about this, use the
 * intermediate level API. You have been warned!
 *
 * ---------------------------------------------------------------------------
 * Vendored into virgil-crypto-c from dsprenkels/sss
 *   upstream commit: 9f2a10b1c0d391bed485c4c7e93788ce37c360f1
 *   license:         MIT (see thirdparty/sss/LICENSE)
 *
 * Modifications from upstream (see thirdparty/sss/VERSION):
 *   1. Public functions prefixed `vscf_sss_*` to avoid symbol collisions in
 *      the flat multi-wrapper symbol table.
 *   2. `vscf_sss_create_keyshares` takes the random polynomial coefficients as
 *      a parameter instead of calling the bundled `randombytes()`. The caller
 *      (vscf_shamir) supplies entropy from virgil's RNG interface. This removes
 *      the `randombytes` dependency and keeps the function thread-safe and
 *      deterministic given its inputs.
 * The GF(256) arithmetic is unchanged from upstream and must remain
 * constant-time -- do not "optimize" it.
 * ---------------------------------------------------------------------------
 */


#ifndef sss_HAZMAT_H_
#define sss_HAZMAT_H_

#include <inttypes.h>


#define sss_KEYSHARE_LEN 33 /* 1 + 32 */


/*
 * One share of a cryptographic key which is shared using Shamir's
 * the `vscf_sss_create_keyshares` function.
 */
typedef uint8_t sss_Keyshare[sss_KEYSHARE_LEN];


/*
 * Share the secret given in `key` into `n` shares with a treshold value given
 * in `k`. The resulting shares are written to `out`.
 *
 * `random_data` must point to `32 * (k - 1)` bytes of uniformly random data,
 * used as the higher-order polynomial coefficients. When `k == 1` no random
 * data is required and `random_data` may be any valid (possibly empty) buffer.
 *
 * The share generation that is done in this function is only secure if the key
 * that is given is indeed a cryptographic key. This means that it should be
 * randomly and uniformly generated string of 32 bytes.
 *
 * Also, for performance reasons, this function assumes that both `n` and `k`
 * are *public* values.
 */
void vscf_sss_create_keyshares(sss_Keyshare *out,
                               const uint8_t key[32],
                               uint8_t n,
                               uint8_t k,
                               const uint8_t *random_data);


/*
 * Combine the `k` shares provided in `shares` and write the resulting key to
 * `key`. The amount of shares used to restore a secret may be larger than the
 * threshold needed to restore them.
 *
 * This function does *not* do *any* checking for integrity. If any of the
 * shares not original, this will result in an invalid resored value.
 * All values written to `key` should be treated as secret. Even if some of the
 * shares that were provided as input were incorrect, the resulting key *still*
 * allows an attacker to gain information about the real key.
 *
 * This function treats `shares` and `key` as secret values. `k` is treated as
 * a public value (for performance reasons).
 */
void vscf_sss_combine_keyshares(uint8_t key[32],
                                const sss_Keyshare *shares,
                                uint8_t k);


#endif /* sss_HAZMAT_H_ */
