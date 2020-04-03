//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


//  @description
// --------------------------------------------------------------------------
//  Utils class for working with protobug.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_pb_utils.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_pb_utils_defs.h"

#include <pb_decode.h>
#include <pb_encode.h>
#include <virgil/crypto/foundation/vscf_simple_alg_info.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_pb_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_pb_utils_init_ctx(vscr_ratchet_pb_utils_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_pb_utils_cleanup_ctx(vscr_ratchet_pb_utils_t *self);

//
//  Return size of 'vscr_ratchet_pb_utils_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_pb_utils_ctx_size(void) {

    return sizeof(vscr_ratchet_pb_utils_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_pb_utils_init(vscr_ratchet_pb_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_pb_utils_t));

    self->refcnt = 1;

    vscr_ratchet_pb_utils_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_pb_utils_cleanup(vscr_ratchet_pb_utils_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_pb_utils_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_pb_utils_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_pb_utils_t *
vscr_ratchet_pb_utils_new(void) {

    vscr_ratchet_pb_utils_t *self = (vscr_ratchet_pb_utils_t *) vscr_alloc(sizeof (vscr_ratchet_pb_utils_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_pb_utils_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_pb_utils_delete(vscr_ratchet_pb_utils_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCR_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCR_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_pb_utils_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_pb_utils_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_pb_utils_destroy(vscr_ratchet_pb_utils_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_pb_utils_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_pb_utils_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_pb_utils_t *
vscr_ratchet_pb_utils_shallow_copy(vscr_ratchet_pb_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
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
//  Note, this method is called automatically when method vscr_ratchet_pb_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_pb_utils_init_ctx(vscr_ratchet_pb_utils_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_pb_utils_cleanup_ctx(vscr_ratchet_pb_utils_t *self) {

    VSCR_ASSERT_PTR(self);
}

VSCR_PUBLIC void
vscr_ratchet_pb_utils_serialize_data(vsc_data_t data, pb_bytes_array_t **pb_buffer_ref) {

    VSCR_ASSERT_PTR(pb_buffer_ref);

    *pb_buffer_ref = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(data.len));
    memcpy((*pb_buffer_ref)->bytes, data.bytes, data.len);
    (*pb_buffer_ref)->size = data.len;
}

VSCR_PUBLIC void
vscr_ratchet_pb_utils_serialize_buffer(vsc_buffer_t *buffer, pb_bytes_array_t **pb_buffer_ref) {

    VSCR_ASSERT_PTR(buffer);

    vscr_ratchet_pb_utils_serialize_data(vsc_buffer_data(buffer), pb_buffer_ref);
}

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_pb_utils_deserialize_buffer(const pb_bytes_array_t *pb_buffer) {

    if (pb_buffer == NULL) {
        return NULL;
    }

    return vsc_buffer_new_with_data(vsc_data(pb_buffer->bytes, pb_buffer->size));
}

VSCR_PUBLIC vsc_data_t
vscr_ratchet_pb_utils_buffer_to_data(const pb_bytes_array_t *pb_buffer) {

    if (pb_buffer == NULL) {
        return vsc_data_empty();
    }

    return vsc_data(pb_buffer->bytes, pb_buffer->size);
}

VSCR_PUBLIC void
vscr_ratchet_pb_utils_serialize_public_key(const vscf_impl_t *key, pb_bytes_array_t **pb_buffer_ref) {

    VSCR_ASSERT_PTR(key);
    VSCR_ASSERT_PTR(pb_buffer_ref);

    VSCR_ASSERT(vscf_impl_tag(key) == vscf_impl_tag_RAW_PUBLIC_KEY);
    vscr_ratchet_pb_utils_serialize_data(vscf_raw_public_key_data((vscf_raw_public_key_t *)key), pb_buffer_ref);
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_pb_utils_deserialize_public_key(
        vscf_round5_t *round5, const pb_bytes_array_t *pb_buffer, vscf_impl_t **public_key_ref) {

    VSCR_ASSERT_PTR(round5);
    VSCR_ASSERT_PTR(pb_buffer);
    VSCR_ASSERT_PTR(public_key_ref);

    // FIXME: Double memory copy

    vsc_data_t data = vsc_data(pb_buffer->bytes, pb_buffer->size);

    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(data, &alg_info);

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    *public_key_ref = vscf_round5_import_public_key(round5, raw_public_key, &error_ctx);

    vscf_raw_public_key_destroy(&raw_public_key);

    if (error_ctx.status != vscf_status_SUCCESS) {
        // FIXME
        return vscr_status_ERROR_RNG_FAILED;
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC void
vscr_ratchet_pb_utils_serialize_private_key(const vscf_impl_t *key, pb_bytes_array_t **pb_buffer_ref) {

    VSCR_ASSERT_PTR(key);
    VSCR_ASSERT_PTR(pb_buffer_ref);

    VSCR_ASSERT(vscf_impl_tag(key) == vscf_impl_tag_RAW_PRIVATE_KEY);
    vscr_ratchet_pb_utils_serialize_data(vscf_raw_public_key_data((vscf_raw_public_key_t *)key), pb_buffer_ref);
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_pb_utils_deserialize_private_key(
        vscf_round5_t *round5, const pb_bytes_array_t *pb_buffer, vscf_impl_t **private_key_ref) {

    VSCR_ASSERT_PTR(round5);
    VSCR_ASSERT_PTR(pb_buffer);
    VSCR_ASSERT_PTR(private_key_ref);

    vsc_data_t data = vsc_data(pb_buffer->bytes, pb_buffer->size);

    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(data, &alg_info);

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    *private_key_ref = vscf_round5_import_private_key(round5, raw_private_key, &error_ctx);

    vscf_raw_private_key_destroy(&raw_private_key);

    if (error_ctx.status != vscf_status_SUCCESS) {
        // FIXME
        return vscr_status_ERROR_RNG_FAILED;
    }

    return vscr_status_SUCCESS;
}
