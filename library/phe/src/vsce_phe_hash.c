//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_phe_hash.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_hash_defs.h"
#include "vsce_const.h"

#include <stdarg.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *self);

static void
vsce_phe_hash_derive_z(vsce_phe_hash_t *self, vsc_data_t buffer, bool success, mbedtls_mpi *z);

static void
vsce_phe_hash_push_points_to_buffer(vsce_phe_hash_t *self, vsc_buffer_t *buffer, size_t count, ...);

//
//  Return size of 'vsce_phe_hash_t'.
//
VSCE_PUBLIC size_t
vsce_phe_hash_ctx_size(void) {

    return sizeof(vsce_phe_hash_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_hash_init(vsce_phe_hash_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_phe_hash_t));

    self->refcnt = 1;

    vsce_phe_hash_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_hash_cleanup(vsce_phe_hash_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_phe_hash_cleanup_ctx(self);

    vsce_zeroize(self, sizeof(vsce_phe_hash_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_new(void) {

    vsce_phe_hash_t *self = (vsce_phe_hash_t *) vsce_alloc(sizeof (vsce_phe_hash_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_phe_hash_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_phe_hash_delete(vsce_phe_hash_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCE_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCE_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsce_phe_hash_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_hash_new ()'.
//
VSCE_PUBLIC void
vsce_phe_hash_destroy(vsce_phe_hash_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_phe_hash_t *self = *self_ref;
    *self_ref = NULL;

    vsce_phe_hash_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_shallow_copy(vsce_phe_hash_t *self) {

    VSCE_ASSERT_PTR(self);

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *self) {

    VSCE_ASSERT_PTR(self);

    self->simple_swu = vscf_simple_swu_new();

    mbedtls_ecp_group_init(&self->group);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_group_load(&self->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_simple_swu_destroy(&self->simple_swu);

    mbedtls_ecp_group_free(&self->group);
}

VSCE_PUBLIC void
vsce_phe_hash_derive_account_key(vsce_phe_hash_t *self, const mbedtls_ecp_point *m, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(m);
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_unused_len(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    byte M_buffer[vsce_phe_common_PHE_POINT_LENGTH];
    vsc_buffer_t M_buf;
    vsc_buffer_init(&M_buf);
    vsc_buffer_use(&M_buf, M_buffer, sizeof(M_buffer));

    size_t olen = 0;
    int mbedtls_status = mbedtls_ecp_point_write_binary(&self->group, m, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(&M_buf), vsce_phe_common_PHE_POINT_LENGTH);
    vsc_buffer_inc_used(&M_buf, vsce_phe_common_PHE_POINT_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));
    vscf_hkdf_set_info(hkdf, k_kdf_info_client_key);
    vscf_hkdf_derive(hkdf, vsc_buffer_data(&M_buf), vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, account_key);

    vsc_buffer_delete(&M_buf);
    vscf_hkdf_destroy(&hkdf);

    vsce_zeroize(M_buffer, sizeof(M_buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hc0(vsce_phe_hash_t *self, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc0) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(hc0);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    enum {
        max_length =
                sizeof(k_dhc0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + vsce_phe_common_PHE_MAX_PASSWORD_LENGTH
    };

    const size_t length = sizeof(k_dhc0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len;

    byte buffer[max_length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, length);

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhc0, sizeof(k_dhc0));
    vsc_buffer_inc_used(&buff, sizeof(k_dhc0));

    memcpy(vsc_buffer_unused_bytes(&buff), nc.bytes, nc.len);
    vsc_buffer_inc_used(&buff, nc.len);

    memcpy(vsc_buffer_unused_bytes(&buff), password.bytes, password.len);
    vsc_buffer_inc_used(&buff, password.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vscf_simple_swu_data_to_point(self->simple_swu, vsc_buffer_data(&buff), hc0);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hc1(vsce_phe_hash_t *self, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc1) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(hc1);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    enum {
        max_length =
                sizeof(k_dhc1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + vsce_phe_common_PHE_MAX_PASSWORD_LENGTH
    };

    const size_t length = sizeof(k_dhc1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len;

    byte buffer[max_length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, length);

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhc1, sizeof(k_dhc1));
    vsc_buffer_inc_used(&buff, sizeof(k_dhc1));

    memcpy(vsc_buffer_unused_bytes(&buff), nc.bytes, nc.len);
    vsc_buffer_inc_used(&buff, nc.len);

    memcpy(vsc_buffer_unused_bytes(&buff), password.bytes, password.len);
    vsc_buffer_inc_used(&buff, password.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vscf_simple_swu_data_to_point(self->simple_swu, vsc_buffer_data(&buff), hc1);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hs0(vsce_phe_hash_t *self, vsc_data_t ns, mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(hs0);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    enum { length = sizeof(k_dhs0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH };

    byte buffer[length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhs0, sizeof(k_dhs0));
    vsc_buffer_inc_used(&buff, sizeof(k_dhs0));

    memcpy(vsc_buffer_unused_bytes(&buff), ns.bytes, ns.len);
    vsc_buffer_inc_used(&buff, ns.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vscf_simple_swu_data_to_point(self->simple_swu, vsc_buffer_data(&buff), hs0);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hs1(vsce_phe_hash_t *self, vsc_data_t ns, mbedtls_ecp_point *hs1) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(hs1);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    enum { length = sizeof(k_dhs1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH };

    byte buffer[length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhs1, sizeof(k_dhs1));
    vsc_buffer_inc_used(&buff, sizeof(k_dhs1));

    memcpy(vsc_buffer_unused_bytes(&buff), ns.bytes, ns.len);
    vsc_buffer_inc_used(&buff, ns.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vscf_simple_swu_data_to_point(self->simple_swu, vsc_buffer_data(&buff), hs1);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

static void
vsce_phe_hash_derive_z(vsce_phe_hash_t *self, vsc_data_t buffer, bool success, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(self);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    byte key_buffer[vscf_sha512_DIGEST_LEN];

    vsc_buffer_t key;
    vsc_buffer_init(&key);
    vsc_buffer_use(&key, key_buffer, sizeof(key_buffer));

    vscf_sha512_hash(buffer, &key);

    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte z_buffer[vsce_phe_common_PHE_HASH_LEN];

    vsc_buffer_t z_buff;
    vsc_buffer_init(&z_buff);
    vsc_buffer_use(&z_buff, z_buffer, sizeof(z_buffer));

    do {
        vsc_buffer_reset(&z_buff);
        int mbedtls_status = mbedtls_mpi_copy(z, &self->group.N);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        vsc_data_t domain = success ? k_proof_ok : k_proof_error;

        vscf_hkdf_reset(hkdf, domain, 0);
        vscf_hkdf_set_info(hkdf, k_kdf_info_z);
        vscf_hkdf_derive(hkdf, vsc_buffer_data(&key), vsce_phe_common_PHE_HASH_LEN, &z_buff);

        mbedtls_status = mbedtls_mpi_read_binary(z, vsc_buffer_bytes(&z_buff), vsc_buffer_len(&z_buff));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    } while (mbedtls_ecp_check_privkey(&self->group, z) != 0);

    vscf_hkdf_destroy(&hkdf);

    vsc_buffer_delete(&key);
    vsce_zeroize(key_buffer, sizeof(key_buffer));
    vsc_buffer_delete(&z_buff);
    vsce_zeroize(z_buffer, sizeof(z_buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hash_z_success(vsce_phe_hash_t *self, const mbedtls_ecp_point *pub, const mbedtls_ecp_point *p2,
        const mbedtls_ecp_point *q2, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(pub);
    VSCE_ASSERT_PTR(p2);
    VSCE_ASSERT_PTR(term1);
    VSCE_ASSERT_PTR(term2);
    VSCE_ASSERT((term3 == NULL && q2 == NULL) || (term3 != NULL && q2 != NULL));

    size_t points_count = 7;

    if (q2 == NULL) {
        points_count = 5;
    }

    byte buffer[7 * vsce_phe_common_PHE_POINT_LENGTH];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, points_count * vsce_phe_common_PHE_POINT_LENGTH);

    // Order is changed for backwards compatibility
    vsce_phe_hash_push_points_to_buffer(self, &buff, 7, pub, &self->group.G, p2, q2, term2, term3, term1);
    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_derive_z(self, vsc_buffer_data(&buff), true, z);

    vsc_buffer_delete(&buff);
}

VSCE_PUBLIC void
vsce_phe_hash_hash_z_failure(vsce_phe_hash_t *self, vsc_data_t server_public_key, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, const mbedtls_ecp_point *term4, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(term1);
    VSCE_ASSERT_PTR(term2);
    VSCE_ASSERT_PTR(term3);
    VSCE_ASSERT_PTR(term4);

    byte buffer[vsce_phe_common_PHE_PUBLIC_KEY_LENGTH + 7 * vsce_phe_common_PHE_POINT_LENGTH];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), server_public_key.bytes, server_public_key.len);
    vsc_buffer_inc_used(&buff, server_public_key.len);

    vsce_phe_hash_push_points_to_buffer(self, &buff, 7, &self->group.G, c0, c1, term1, term2, term3, term4);
    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_derive_z(self, vsc_buffer_data(&buff), false, z);

    vsc_buffer_delete(&buff);
}

static void
vsce_phe_hash_push_points_to_buffer(vsce_phe_hash_t *self, vsc_buffer_t *buffer, size_t count, ...) {

    va_list points;

    va_start(points, count);

    size_t olen = 0;
    int mbedtls_status = 0;

    for (size_t i = 0; i < count; i++) {
        const mbedtls_ecp_point *p = va_arg(points, const mbedtls_ecp_point *);

        if (p != NULL) {
            mbedtls_ecp_point_write_binary(&self->group, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                    vsc_buffer_unused_bytes(buffer), vsc_buffer_unused_len(buffer));
            vsc_buffer_inc_used(buffer, olen);
            VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
            VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
        }
    }

    va_end(points);
}
