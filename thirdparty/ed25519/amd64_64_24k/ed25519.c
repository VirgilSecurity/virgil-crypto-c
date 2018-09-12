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
 *
 * Low level implementation was taken from Orson Peters library,
 *     see https://github.com/orlp/ed25519 and license.txt file
 */

#include <string.h>

#include "ed25519.h"
#include "ed25519_sha512.h"

#include "fe25519.h"
#include "sc25519.h"
#include "ge25519.h"

/* Implementation that should never be optimized out by the compiler */
static void ed25519_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

static void fe25519_copy(fe25519* dst, const fe25519* src) {
    unsigned long long f0 = src->v[0];
    unsigned long long f1 = src->v[1];
    unsigned long long f2 = src->v[2];
    unsigned long long f3 = src->v[3];

    dst->v[0] = f0;
    dst->v[1] = f1;
    dst->v[2] = f2;
    dst->v[3] = f3;
}

static void fe25519_cswap_local(fe25519* r, fe25519* x, unsigned long long b) {
    unsigned long long r0 = r->v[0];
    unsigned long long r1 = r->v[1];
    unsigned long long r2 = r->v[2];
    unsigned long long r3 = r->v[3];

    unsigned long long x0 = x->v[0];
    unsigned long long x1 = x->v[1];
    unsigned long long x2 = x->v[2];
    unsigned long long x3 = x->v[3];

    unsigned long long s0 = r0 ^ x0;
    unsigned long long s1 = r1 ^ x1;
    unsigned long long s2 = r2 ^ x2;
    unsigned long long s3 = r3 ^ x3;
    b = (unsigned long long) (-(long) b); /* silence warning */
    s0 &= b;
    s1 &= b;
    s2 &= b;
    s3 &= b;
    r->v[0] = r0 ^ s0;
    r->v[1] = r1 ^ s1;
    r->v[2] = r2 ^ s2;
    r->v[3] = r3 ^ s3;
    x->v[0] = x0 ^ s0;
    x->v[1] = x1 ^ s1;
    x->v[2] = x2 ^ s2;
    x->v[3] = x3 ^ s3;
}

void fe25519_mul121666(fe25519 *r, const fe25519 *x) {
    fe25519 fe_121666;

    fe25519_setint(&fe_121666, 121666);
    fe25519_mul(r, x, &fe_121666);
}

int ed25519_get_pubkey(unsigned char public_key[32], const unsigned char secret_key[32]) {
    sc25519 scsk;
    ge25519 gepk;

    unsigned char az[64];

    ed25519_sha512(secret_key, 32, az, 0);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    sc25519_from32bytes(&scsk, az);
    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(public_key, &gepk);

    ed25519_zeroize(az, sizeof(az));
    return 0;
}

/*
 * due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
 */
int ed25519_pubkey_to_curve25519(
        unsigned char curve_public_key[32], const unsigned char ed_public_key[32]) {

    fe25519 x1, tmp0, tmp1;

    fe25519_unpack(&x1, ed_public_key);
    fe25519_setint(&tmp1, 1);
    fe25519_add(&tmp0, &x1, &tmp1);
    fe25519_sub(&tmp1, &tmp1, &x1);
    fe25519_invert(&tmp1, &tmp1);
    fe25519_mul(&x1, &tmp0, &tmp1);

    fe25519_pack(curve_public_key, &x1);

    return 0;
}

int ed25519_key_to_curve25519(
        unsigned char curve_secret_key[32], const unsigned char ed_secret_key[32]) {

    unsigned char az[64];

    ed25519_sha512(ed_secret_key, 32, az, 0);
    memcpy(curve_secret_key, az, 32);
    ed25519_zeroize(az, sizeof(az));

    return 0;
}


int ed25519_sign(
        unsigned char signature[64],
        const unsigned char secret_key[32],
        const unsigned char* msg, size_t msg_len) {

    ed25519_sha512_context hash;
    unsigned char hram[64];
    unsigned char nonce[64];
    unsigned char az[64];
    unsigned char public_key[32];
    sc25519 sck, scs, scsk;
    ge25519 R, gepk;

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, secret_key, 32);
    ed25519_sha512_finish(&hash, az);

    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    sc25519_from32bytes(&scsk, az);
    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(public_key, &gepk);

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, az + 32, 32);
    ed25519_sha512_update(&hash, msg, msg_len);
    ed25519_sha512_finish(&hash, nonce);

    sc25519_from64bytes(&sck, nonce);
    ge25519_scalarmult_base(&R, &sck);
    ge25519_pack(signature, &R);

    memmove(signature + 32, public_key, 32);

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, signature, 64);
    ed25519_sha512_update(&hash, msg, msg_len);
    ed25519_sha512_finish(&hash, hram);

    sc25519_from64bytes(&scs, hram);
    sc25519_mul(&scs, &scs, &scsk);
    sc25519_add(&scs, &scs, &sck);

    sc25519_to32bytes(signature + 32, &scs);

    ed25519_zeroize(nonce, sizeof(nonce));
    ed25519_zeroize(az, sizeof(az));
    ed25519_sha512_free(&hash);

    return 0;
}

static int consttime_equal(const unsigned char* x, const unsigned char* y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
#define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
#undef F

    return !r;
}

int ed25519_verify(
        const unsigned char signature[64],
        const unsigned char public_key[32],
        const unsigned char* msg, size_t msg_len) {

    ed25519_sha512_context hash;
    unsigned char h[64];
    unsigned char checker[32];
    sc25519 sck, scs;
    ge25519 A, R;


    if (signature[63] & 224) {
        return 1;
    }

    if (ge25519_unpackneg_vartime(&A, public_key) != 0) {
        return 1;
    }

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, signature, 32);
    ed25519_sha512_update(&hash, public_key, 32);
    ed25519_sha512_update(&hash, msg, msg_len);
    ed25519_sha512_finish(&hash, h);

    sc25519_from64bytes(&sck, h);
    sc25519_from32bytes(&scs, signature + 32);
    ge25519_double_scalarmult_vartime(&R, &A, &sck, &scs);
    ge25519_pack(checker, &R);

    if (!consttime_equal(checker, signature)) {
        return 2;
    }

    return 0;
}

/**
 * @brief Derive Curve25519 public key from the secret key.
 * @param[out] public_key Curve25519 public key.
 * @param[in] secret_key Curve25519 secret key.
 * @return 0 if success, non zero - otherwise.
 */
int curve25519_get_pubkey(unsigned char public_key[32], const unsigned char secret_key[32]) {
    sc25519 scsk;
    ge25519 gepk;

    unsigned char e[32];

    memcpy(e, secret_key, sizeof(e));

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    sc25519_from32bytes(&scsk, e);
    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(public_key, &gepk);

    ed25519_pubkey_to_curve25519(public_key, public_key);

    ed25519_zeroize(e, sizeof(e));
    return 0;
}

int curve25519_key_exchange(
        unsigned char shared_secret[32], const unsigned char public_key[32], const unsigned char secret_key[32]) {

    fe25519 x1;
    fe25519 x2;
    fe25519 z2;
    fe25519 x3;
    fe25519 z3;
    fe25519 tmp0;
    fe25519 tmp1;

    int pos;
    unsigned long long swap;
    unsigned long long b;
    unsigned char e[32];

    fe25519_unpack(&x1, public_key);

    fe25519_setint(&x2, 1);
    fe25519_setint(&z2, 0);
    fe25519_copy(&x3, &x1);
    fe25519_setint(&z3, 1);

    memcpy(e, secret_key, sizeof(e));

    e[0] &= 248;
    e[31] &= 63;
    e[31] |= 64;

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe25519_cswap_local(&x2, &x3, swap);
        fe25519_cswap_local(&z2, &z3, swap);
        swap = b;

        /* from montgomery.h */
        fe25519_sub(&tmp0, &x3, &z3);
        fe25519_sub(&tmp1, &x2, &z2);
        fe25519_add(&x2, &x2, &z2);
        fe25519_add(&z2, &x3, &z3);
        fe25519_mul(&z3, &tmp0, &x2);
        fe25519_mul(&z2, &z2, &tmp1);
        fe25519_square(&tmp0, &tmp1);
        fe25519_square(&tmp1, &x2);
        fe25519_add(&x3, &z3, &z2);
        fe25519_sub(&z2, &z3, &z2);
        fe25519_mul(&x2, &tmp1, &tmp0);
        fe25519_sub(&tmp1, &tmp1, &tmp0);
        fe25519_square(&z2, &z2);
        fe25519_mul121666(&z3, &tmp1);
        fe25519_square(&x3, &x3);
        fe25519_add(&tmp0, &tmp0, &z3);
        fe25519_mul(&z3, &x1, &z2);
        fe25519_mul(&z2, &tmp1, &tmp0);
    }

    fe25519_cswap_local(&x2, &x3, swap);
    fe25519_cswap_local(&z2, &z3, swap);

    fe25519_invert(&z2, &z2);
    fe25519_mul(&x2, &x2, &z2);
    fe25519_pack(shared_secret, &x2);

    ed25519_zeroize(e, sizeof(e));
    /* The all-zero output results when the input is a point of small order. */
    return fe25519_iszero_vartime(&x2) ? (-1) : (0);
}

//////////////////////////////////////////////////////////////////

/*
 * edwardsY = (montgomeryX - 1)*inverse(montgomeryX + 1) mod p
 */
static int x25519_ext_montgomery_to_edwards_pubkey(
        unsigned char ed_public_key[32], const unsigned char curve_public_key[32]) {

    fe25519 mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one, one, ed_y;

    fe25519_unpack(&mont_x, curve_public_key);
    fe25519_setint(&one, 1);
    fe25519_sub(&mont_x_minus_one, &mont_x, &one);
    fe25519_add(&mont_x_plus_one, &mont_x, &one);
    fe25519_invert(&inv_mont_x_plus_one, &mont_x_plus_one);
    fe25519_mul(&ed_y, &mont_x_minus_one, &inv_mont_x_plus_one);
    fe25519_pack(ed_public_key, &ed_y);

    return 0;
}

static int ed25519_sign_az(
        unsigned char signature[64],
        const unsigned char az[64],
        const unsigned char* msg, size_t msg_len) {

    ed25519_sha512_context hash;
    unsigned char hram[64];
    unsigned char nonce[64];
    unsigned char public_key[32];
    sc25519 sck, scs, scsk;
    ge25519 R, gepk;

    sc25519_from32bytes(&scsk, az);
    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(public_key, &gepk);

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, az + 32, 32);
    ed25519_sha512_update(&hash, msg, msg_len);
    ed25519_sha512_finish(&hash, nonce);

    sc25519_from64bytes(&sck, nonce);
    ge25519_scalarmult_base(&R, &sck);
    ge25519_pack(signature, &R);

    memmove(signature + 32, public_key, 32);

    ed25519_sha512_starts(&hash, 0);
    ed25519_sha512_update(&hash, signature, 64);
    ed25519_sha512_update(&hash, msg, msg_len);
    ed25519_sha512_finish(&hash, hram);

    sc25519_from64bytes(&scs, hram);
    sc25519_mul(&scs, &scs, &scsk);
    sc25519_add(&scs, &scs, &sck);

    sc25519_to32bytes(signature + 32, &scs);

    ed25519_zeroize(nonce, sizeof(nonce));
    ed25519_sha512_free(&hash);

    return 0;
}

int curve25519_sign(
        unsigned char signature[64],
        const unsigned char secret_key[32],
        const unsigned char* msg, size_t msg_len)
{

    unsigned char ed_public_key[32];

    unsigned char az[64];
    unsigned char sign_bit = 0;
    ge25519 A;
    sc25519 scsk;

    ed25519_sha512(secret_key, 32, az, 0);
    memcpy(az, secret_key, 32);

    sc25519_from32bytes(&scsk, az);
    ge25519_scalarmult_base(&A, &scsk);
    ge25519_pack(ed_public_key, &A);

    sign_bit = ed_public_key[31] & (unsigned char) 0x80;

    ed25519_sign_az(signature, az, msg, msg_len);

    signature[63] &= 0x7F;  // bit should be zero already, but just in case
    signature[63] |= sign_bit;

    ed25519_zeroize(az, sizeof(az));
    return 0;
}


int curve25519_verify(
        const unsigned char signature[64],
        const unsigned char public_key[32],
        const unsigned char* msg, size_t msg_len)
{
    unsigned char ed_public_key[32];

    unsigned char fixed_signature[64];

    x25519_ext_montgomery_to_edwards_pubkey(ed_public_key, public_key);
    ed_public_key[31] |= (signature[63] & 0x80);

    memmove(fixed_signature, signature, 64);

    fixed_signature[63] &= 0x7F;

    return ed25519_verify(fixed_signature, ed_public_key, msg, msg_len);
}
