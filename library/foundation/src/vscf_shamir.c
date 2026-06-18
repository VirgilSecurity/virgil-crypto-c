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
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_shamir.h"
#include "vscf_memory.h"
#include "vscf_assert.h"

// clang-format on
//  @end

//  Dependencies used by the hand-written implementation below. Declared in the
//  user-editable region so they are preserved across codegen regeneration.
#include "vscf_shamir_defs.h"
#include "vscf_random.h"
#include "vscf_ctr_drbg.h"
#include "vscf_sha256.h"
#include "vscf_aes256_gcm.h"
#include "hazmat.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <string.h>


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_shamir_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_shamir_init_ctx(vscf_shamir_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_shamir_cleanup_ctx(vscf_shamir_t *self);

//
//  Return size of 'vscf_shamir_t'.
//
VSCF_PUBLIC size_t
vscf_shamir_ctx_size(void) {

    return sizeof(vscf_shamir_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_shamir_init(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_shamir_t));

    self->refcnt = 1;

    vscf_shamir_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_shamir_cleanup(vscf_shamir_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_shamir_cleanup_ctx(self);

    vscf_shamir_release_random(self);

    vscf_zeroize(self, sizeof(vscf_shamir_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_shamir_t *
vscf_shamir_new(void) {

    vscf_shamir_t *self = (vscf_shamir_t *) vscf_alloc(sizeof (vscf_shamir_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_shamir_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_shamir_delete(vscf_shamir_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_shamir_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_shamir_new ()'.
//
VSCF_PUBLIC void
vscf_shamir_destroy(vscf_shamir_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_shamir_t *self = *self_ref;
    *self_ref = NULL;

    vscf_shamir_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_shamir_t *
vscf_shamir_shallow_copy(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_shamir_use_random(vscf_shamir_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_shamir_take_random(vscf_shamir_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_shamir_release_random(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end

// --------------------------------------------------------------------------
//  Shamir secret sharing implementation (split-key-encrypt-data).
//
//  Each self-contained share has the layout (all shares of one split are equal
//  length; only the trailing key-share differs):
//
//    offset  field            size   notes
//    0       format version   1
//    1       aead id          1      1 = AES-256-GCM
//    2       threshold (k)    1
//    3       share count (n)  1
//    4       split id         16     random, binds shares of one split together
//    20      nonce            12     AEAD nonce (random, single-use key)
//    32      commitment       32     SHA-256(data key)
//    64      aead length      4      big-endian, length of (ciphertext||tag)
//    68      ciphertext||tag  L      AES-256-GCM output (tag appended)
//    68+L    key-share        33     dsprenkels/sss key-share (index||y)
//
//  Bytes [0, 64) (everything up to and including the commitment) are the AEAD
//  associated data, so tampering with k/n/split-id/nonce/commitment is caught
//  by the tag. The commitment is additionally verified before decryption, so a
//  wrong reconstructed key is rejected without relying on the (non key
//  committing) AEAD.
// --------------------------------------------------------------------------

enum {
    vscf_shamir_FORMAT_VERSION = 1,
    vscf_shamir_AEAD_ID_AES256_GCM = 1,
    vscf_shamir_SPLIT_ID_LEN = 16,
    vscf_shamir_MAX_SHARES = 255,

    vscf_shamir_DK_LEN = vscf_aes256_gcm_KEY_LEN,
    vscf_shamir_NONCE_LEN = vscf_aes256_gcm_NONCE_LEN,
    vscf_shamir_TAG_LEN = vscf_aes256_gcm_AUTH_TAG_LEN,
    vscf_shamir_COMMITMENT_LEN = vscf_sha256_DIGEST_LEN,
    vscf_shamir_AEAD_LEN_FIELD = 4,

    vscf_shamir_POS_VERSION = 0,
    vscf_shamir_POS_AEAD_ID = 1,
    vscf_shamir_POS_THRESHOLD = 2,
    vscf_shamir_POS_SHARE_COUNT = 3,
    vscf_shamir_POS_SPLIT_ID = 4,
    vscf_shamir_POS_NONCE = vscf_shamir_POS_SPLIT_ID + vscf_shamir_SPLIT_ID_LEN,
    vscf_shamir_POS_COMMITMENT = vscf_shamir_POS_NONCE + vscf_shamir_NONCE_LEN,
    vscf_shamir_POS_AEAD_LEN = vscf_shamir_POS_COMMITMENT + vscf_shamir_COMMITMENT_LEN,

    //  Length of the AEAD associated data == header up to and incl. commitment.
    vscf_shamir_AAD_LEN = vscf_shamir_POS_AEAD_LEN,
    //  Length of the fixed header (up to and including the aead-length field).
    vscf_shamir_HEADER_LEN = vscf_shamir_POS_AEAD_LEN + vscf_shamir_AEAD_LEN_FIELD,
    //  Per-share overhead that is not the AEAD output (header + key-share).
    vscf_shamir_OVERHEAD_LEN = vscf_shamir_HEADER_LEN + sss_KEYSHARE_LEN,
    //  Worst-case AEAD expansion used to size the output buffer.
    vscf_shamir_AEAD_OVERHEAD = vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN
};

static void
vscf_shamir_store_u32_be(byte out[4], uint32_t value) {
    out[0] = (byte)(value >> 24);
    out[1] = (byte)(value >> 16);
    out[2] = (byte)(value >> 8);
    out[3] = (byte)(value);
}

static uint32_t
vscf_shamir_load_u32_be(const byte in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

//
//  Perform context specific initialization.
//
static void
vscf_shamir_init_ctx(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//
static void
vscf_shamir_cleanup_ctx(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Setup predefined values to the uninitialized class dependencies:
//  a CTR DRBG random number generator.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_setup_defaults(vscf_shamir_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }
        self->random = vscf_ctr_drbg_impl(random);
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate the length in bytes of a single share produced for a secret
//  of the given length.
//
VSCF_PUBLIC size_t
vscf_shamir_share_len(const vscf_shamir_t *self, size_t secret_len) {

    VSCF_ASSERT_PTR(self);

    return vscf_shamir_HEADER_LEN + secret_len + vscf_shamir_AEAD_OVERHEAD + sss_KEYSHARE_LEN;
}

//
//  Calculate the length in bytes of the buffer needed to hold all shares
//  produced by 'split'.
//
VSCF_PUBLIC size_t
vscf_shamir_shares_len(const vscf_shamir_t *self, size_t secret_len, size_t share_count) {

    VSCF_ASSERT_PTR(self);

    return vscf_shamir_share_len(self, secret_len) * share_count;
}

//
//  Calculate an upper bound on the length in bytes of the recovered secret.
//  The exact length is set on the output buffer by 'combine'.
//
VSCF_PUBLIC size_t
vscf_shamir_recovered_secret_len(const vscf_shamir_t *self, size_t shares_len, size_t share_count) {

    VSCF_ASSERT_PTR(self);

    if (share_count == 0) {
        return 0;
    }

    size_t stride = shares_len / share_count;
    if (stride <= vscf_shamir_OVERHEAD_LEN) {
        return 0;
    }

    //  The plaintext is at most the AEAD output region (which also holds the tag).
    return stride - vscf_shamir_OVERHEAD_LEN;
}

//
//  Split the given secret into 'share count' shares with reconstruction
//  'threshold'.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_split(vscf_shamir_t *self, vsc_data_t secret, size_t threshold, size_t share_count, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(secret));
    VSCF_ASSERT_PTR(out);

    if (NULL == self->random) {
        return vscf_status_ERROR_UNINITIALIZED;
    }

    if (threshold < 1 || share_count < threshold || share_count > vscf_shamir_MAX_SHARES) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_shamir_shares_len(self, secret.len, share_count));

    const uint8_t k = (uint8_t)threshold;
    const uint8_t n = (uint8_t)share_count;

    vscf_status_t status = vscf_status_SUCCESS;
    vsc_buffer_t wrap;
    byte data_key[vscf_shamir_DK_LEN];
    byte nonce[vscf_shamir_NONCE_LEN];
    byte header[vscf_shamir_HEADER_LEN];
    byte *coeffs = NULL;
    byte *key_shares = NULL;
    vscf_aes256_gcm_t *aes = NULL;
    vsc_buffer_t *aead = NULL;

    const size_t coeffs_len = (size_t)(k - 1) * sizeof(uint32_t[8]);
    vscf_zeroize(header, sizeof(header));

    //  1. Data key.
    vsc_buffer_init(&wrap);
    vsc_buffer_use(&wrap, data_key, sizeof(data_key));
    status = vscf_random(self->random, vscf_shamir_DK_LEN, &wrap);
    vsc_buffer_cleanup(&wrap);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    //  2. Nonce.
    vsc_buffer_init(&wrap);
    vsc_buffer_use(&wrap, nonce, sizeof(nonce));
    status = vscf_random(self->random, vscf_shamir_NONCE_LEN, &wrap);
    vsc_buffer_cleanup(&wrap);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    //  3. Build the header: version, aead id, k, n, split id, nonce, commitment.
    header[vscf_shamir_POS_VERSION] = vscf_shamir_FORMAT_VERSION;
    header[vscf_shamir_POS_AEAD_ID] = vscf_shamir_AEAD_ID_AES256_GCM;
    header[vscf_shamir_POS_THRESHOLD] = k;
    header[vscf_shamir_POS_SHARE_COUNT] = n;

    //  3a. Split id (random, binds the shares together).
    vsc_buffer_init(&wrap);
    vsc_buffer_use(&wrap, header + vscf_shamir_POS_SPLIT_ID, vscf_shamir_SPLIT_ID_LEN);
    status = vscf_random(self->random, vscf_shamir_SPLIT_ID_LEN, &wrap);
    vsc_buffer_cleanup(&wrap);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    memcpy(header + vscf_shamir_POS_NONCE, nonce, vscf_shamir_NONCE_LEN);

    //  3b. Commitment = SHA-256(data key), written straight into the header.
    vsc_buffer_init(&wrap);
    vsc_buffer_use(&wrap, header + vscf_shamir_POS_COMMITMENT, vscf_shamir_COMMITMENT_LEN);
    vscf_sha256_hash(vsc_data(data_key, sizeof(data_key)), &wrap);
    vsc_buffer_cleanup(&wrap);

    //  4. Random polynomial coefficients for the share math (32 * (k - 1) bytes).
    coeffs = vscf_alloc(coeffs_len == 0 ? 1 : coeffs_len);
    if (coeffs_len > 0) {
        vsc_buffer_init(&wrap);
        vsc_buffer_use(&wrap, coeffs, coeffs_len);
        status = vscf_random(self->random, coeffs_len, &wrap);
        vsc_buffer_cleanup(&wrap);
        if (status != vscf_status_SUCCESS) {
            goto cleanup;
        }
    }

    //  5. Encrypt the secret with the data key; header is the associated data.
    aes = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_key(aes, vsc_data(data_key, sizeof(data_key)));
    vscf_aes256_gcm_set_nonce(aes, vsc_data(nonce, sizeof(nonce)));
    aead = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_encrypted_len(aes, secret.len));
    status = vscf_aes256_gcm_auth_encrypt(aes, secret, vsc_data(header, vscf_shamir_AAD_LEN), aead, NULL);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    const size_t aead_len = vsc_buffer_len(aead);

    //  6. Shamir-split the data key.
    key_shares = vscf_alloc((size_t)n * sss_KEYSHARE_LEN);
    vscf_sss_create_keyshares((sss_Keyshare *)key_shares, data_key, n, k, coeffs);

    //  7. Assemble the self-contained shares into the output buffer.
    byte aead_len_be[vscf_shamir_AEAD_LEN_FIELD];
    vscf_shamir_store_u32_be(aead_len_be, (uint32_t)aead_len);
    for (size_t i = 0; i < n; ++i) {
        vsc_buffer_write_data(out, vsc_data(header, vscf_shamir_AAD_LEN));
        vsc_buffer_write_data(out, vsc_data(aead_len_be, sizeof(aead_len_be)));
        vsc_buffer_write_data(out, vsc_data(vsc_buffer_bytes(aead), aead_len));
        vsc_buffer_write_data(out, vsc_data(key_shares + i * sss_KEYSHARE_LEN, sss_KEYSHARE_LEN));
    }

cleanup:
    vscf_erase(data_key, sizeof(data_key));
    if (coeffs != NULL) {
        vscf_erase(coeffs, coeffs_len == 0 ? 1 : coeffs_len);
        vscf_dealloc(coeffs);
    }
    if (key_shares != NULL) {
        vscf_erase(key_shares, (size_t)n * sss_KEYSHARE_LEN);
        vscf_dealloc(key_shares);
    }
    vscf_aes256_gcm_destroy(&aes);
    vsc_buffer_destroy(&aead);

    if (status != vscf_status_SUCCESS && vsc_buffer_len(out) > 0) {
        vscf_erase(vsc_buffer_begin(out), vsc_buffer_capacity(out));
        vsc_buffer_reset(out);
    }

    return status;
}

//
//  Reconstruct the secret from 'share count' shares concatenated in 'shares'.
//
VSCF_PUBLIC vscf_status_t
vscf_shamir_combine(const vscf_shamir_t *self, vsc_data_t shares, size_t share_count, vsc_buffer_t *secret) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(shares));
    VSCF_ASSERT_PTR(secret);

    if (share_count < 1 || share_count > vscf_shamir_MAX_SHARES) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    if (shares.len == 0 || shares.len % share_count != 0) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    const size_t stride = shares.len / share_count;
    if (stride <= vscf_shamir_OVERHEAD_LEN) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    const size_t aead_len = stride - vscf_shamir_OVERHEAD_LEN;
    if (aead_len < vscf_shamir_TAG_LEN) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    const byte *share0 = shares.bytes;
    if (share0[vscf_shamir_POS_VERSION] != vscf_shamir_FORMAT_VERSION ||
            share0[vscf_shamir_POS_AEAD_ID] != vscf_shamir_AEAD_ID_AES256_GCM) {
        return vscf_status_ERROR_BAD_ARGUMENTS;
    }

    vscf_status_t status = vscf_status_SUCCESS;
    byte *key_shares = vscf_alloc(share_count * sss_KEYSHARE_LEN);
    vscf_aes256_gcm_t *aes = NULL;
    byte data_key[vscf_shamir_DK_LEN];
    byte commitment[vscf_shamir_COMMITMENT_LEN];
    vsc_buffer_t wrap;
    vscf_zeroize(data_key, sizeof(data_key));

    //  Validate every share, enforce a single consistent (authenticated) header,
    //  and collect the key-shares. The ciphertext copies are NOT compared: they
    //  are authenticated by the AEAD tag, and requiring byte-equality would let a
    //  single tampered copy deny recovery despite enough valid shares.
    for (size_t i = 0; i < share_count; ++i) {
        const byte *share = shares.bytes + i * stride;

        if (share[vscf_shamir_POS_VERSION] != vscf_shamir_FORMAT_VERSION ||
                share[vscf_shamir_POS_AEAD_ID] != vscf_shamir_AEAD_ID_AES256_GCM) {
            status = vscf_status_ERROR_BAD_ARGUMENTS;
            goto cleanup;
        }

        if (vscf_shamir_load_u32_be(share + vscf_shamir_POS_AEAD_LEN) != (uint32_t)aead_len) {
            status = vscf_status_ERROR_BAD_ARGUMENTS;
            goto cleanup;
        }

        if (i > 0 && !vscf_memory_secure_equal(share, share0, vscf_shamir_AAD_LEN)) {
            status = vscf_status_ERROR_BAD_ARGUMENTS;
            goto cleanup;
        }

        memcpy(key_shares + i * sss_KEYSHARE_LEN, share + vscf_shamir_HEADER_LEN + aead_len, sss_KEYSHARE_LEN);

        //  A zero x-coordinate is invalid; the secret lives at x == 0.
        if (key_shares[i * sss_KEYSHARE_LEN] == 0) {
            status = vscf_status_ERROR_BAD_ARGUMENTS;
            goto cleanup;
        }
    }

    //  Reject duplicate x-coordinates: colliding indices divide by zero in the
    //  GF(256) interpolation and silently yield garbage.
    for (size_t i = 0; i < share_count; ++i) {
        for (size_t j = i + 1; j < share_count; ++j) {
            if (key_shares[i * sss_KEYSHARE_LEN] == key_shares[j * sss_KEYSHARE_LEN]) {
                status = vscf_status_ERROR_BAD_ARGUMENTS;
                goto cleanup;
            }
        }
    }

    //  Reconstruct the data key and verify the commitment BEFORE touching the
    //  AEAD, so a wrong/insufficient set fails here and the cipher never runs on
    //  a wrong key.
    vscf_sss_combine_keyshares(data_key, (const sss_Keyshare *)key_shares, (uint8_t)share_count);

    vsc_buffer_init(&wrap);
    vsc_buffer_use(&wrap, commitment, sizeof(commitment));
    vscf_sha256_hash(vsc_data(data_key, sizeof(data_key)), &wrap);
    vsc_buffer_cleanup(&wrap);

    if (!vscf_memory_secure_equal(commitment, share0 + vscf_shamir_POS_COMMITMENT, vscf_shamir_COMMITMENT_LEN)) {
        status = vscf_status_ERROR_SHAMIR_RECOVERY_FAILED;
        goto cleanup;
    }

    //  Authenticated decryption. The header is the associated data; the tag is
    //  the trailing bytes of the AEAD output.
    const byte *aead = share0 + vscf_shamir_HEADER_LEN;
    vsc_data_t ciphertext = vsc_data(aead, aead_len - vscf_shamir_TAG_LEN);
    vsc_data_t tag = vsc_data(aead + aead_len - vscf_shamir_TAG_LEN, vscf_shamir_TAG_LEN);

    aes = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_key(aes, vsc_data(data_key, sizeof(data_key)));
    vscf_aes256_gcm_set_nonce(aes, vsc_data(share0 + vscf_shamir_POS_NONCE, vscf_shamir_NONCE_LEN));
    status = vscf_aes256_gcm_auth_decrypt(aes, ciphertext, vsc_data(share0, vscf_shamir_AAD_LEN), tag, secret);
    if (status != vscf_status_SUCCESS) {
        status = vscf_status_ERROR_SHAMIR_RECOVERY_FAILED;
    }

cleanup:
    vscf_erase(data_key, sizeof(data_key));
    if (key_shares != NULL) {
        vscf_erase(key_shares, share_count * sss_KEYSHARE_LEN);
        vscf_dealloc(key_shares);
    }
    vscf_aes256_gcm_destroy(&aes);

    if (status != vscf_status_SUCCESS && vsc_buffer_capacity(secret) > 0) {
        vscf_erase(vsc_buffer_begin(secret), vsc_buffer_capacity(secret));
        vsc_buffer_reset(secret);
    }

    return status;
}
