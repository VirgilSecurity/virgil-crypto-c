//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Represent signature of "raw card content" snapshot.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_raw_card_signature.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_raw_card_signature_defs.h"
#include "vssc_json_object.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_signature_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_signature_init_ctx(vssc_raw_card_signature_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_signature_cleanup_ctx(vssc_raw_card_signature_t *self);

//
//  Create Raw Card Signature with mandatory properties.
//
static void
vssc_raw_card_signature_init_ctx_with_signature(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature);

//
//  Create Raw Card Signature with mandatory properties.
//
static void
vssc_raw_card_signature_init_ctx_with_signature_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref);

//
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
static void
vssc_raw_card_signature_init_ctx_with_extra_fields(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature, const vssc_json_object_t *extra_fields);

//
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
static void
vssc_raw_card_signature_init_ctx_with_extra_fields_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vssc_json_object_t **extra_fields_ref);

//
//  Perform initialization of pre-allocated context.
//  Create raw card signature with imported values.
//
static void
vssc_raw_card_signature_init_with_imported(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref);

//
//  Create raw card signature with imported values.
//
static void
vssc_raw_card_signature_init_ctx_with_imported(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref);

//
//  Allocate class context and perform it's initialization.
//  Create raw card signature with imported values.
//
static vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_imported(vsc_str_t signer_id, vsc_buffer_t **signature_ref,
        vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref);

//
//  JSON key: signer
//
static const char k_json_key_signer_id_chars[] = "signer";

//
//  JSON key: signer
//
static const vsc_str_t k_json_key_signer_id = {
    k_json_key_signer_id_chars,
    sizeof(k_json_key_signer_id_chars) - 1
};

//
//  JSON key: snapshot
//
static const char k_json_key_snapshot_chars[] = "snapshot";

//
//  JSON key: snapshot
//
static const vsc_str_t k_json_key_snapshot = {
    k_json_key_snapshot_chars,
    sizeof(k_json_key_snapshot_chars) - 1
};

//
//  JSON key: signature
//
static const char k_json_key_signature_chars[] = "signature";

//
//  JSON key: signature
//
static const vsc_str_t k_json_key_signature = {
    k_json_key_signature_chars,
    sizeof(k_json_key_signature_chars) - 1
};

//
//  Return size of 'vssc_raw_card_signature_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_signature_ctx_size(void) {

    return sizeof(vssc_raw_card_signature_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init(vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_signature_cleanup(vssc_raw_card_signature_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_raw_card_signature_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new(void) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init_with_signature(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx_with_signature(self, signer_id, signature);
}

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_signature(vsc_str_t signer_id, vsc_data_t signature) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init_with_signature(self, signer_id, signature);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PRIVATE void
vssc_raw_card_signature_init_with_signature_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx_with_signature_disown(self, signer_id, signature_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with mandatory properties.
//
VSSC_PRIVATE vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_signature_disown(vsc_str_t signer_id, vsc_buffer_t **signature_ref) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init_with_signature_disown(self, signer_id, signature_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PUBLIC void
vssc_raw_card_signature_init_with_extra_fields(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature, const vssc_json_object_t *extra_fields) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx_with_extra_fields(self, signer_id, signature, extra_fields);
}

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_extra_fields(vsc_str_t signer_id, vsc_data_t signature,
        const vssc_json_object_t *extra_fields) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init_with_extra_fields(self, signer_id, signature, extra_fields);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PRIVATE void
vssc_raw_card_signature_init_with_extra_fields_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vssc_json_object_t **extra_fields_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx_with_extra_fields_disown(self, signer_id, signature_ref, extra_fields_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
VSSC_PRIVATE vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_extra_fields_disown(vsc_str_t signer_id, vsc_buffer_t **signature_ref,
        vssc_json_object_t **extra_fields_ref) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init_with_extra_fields_disown(self, signer_id, signature_ref, extra_fields_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create raw card signature with imported values.
//
static void
vssc_raw_card_signature_init_with_imported(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_signature_t));

    self->refcnt = 1;

    vssc_raw_card_signature_init_ctx_with_imported(self, signer_id, signature_ref, snapshot_ref, extra_fields_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create raw card signature with imported values.
//
static vssc_raw_card_signature_t *
vssc_raw_card_signature_new_with_imported(vsc_str_t signer_id, vsc_buffer_t **signature_ref,
        vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref) {

    vssc_raw_card_signature_t *self = (vssc_raw_card_signature_t *) vssc_alloc(sizeof (vssc_raw_card_signature_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_signature_init_with_imported(self, signer_id, signature_ref, snapshot_ref, extra_fields_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_signature_delete(const vssc_raw_card_signature_t *self) {

    vssc_raw_card_signature_t *local_self = (vssc_raw_card_signature_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssc_raw_card_signature_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_signature_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_signature_destroy(vssc_raw_card_signature_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_raw_card_signature_t *self = *self_ref;
    *self_ref = NULL;

    vssc_raw_card_signature_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_shallow_copy(vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_raw_card_signature_t *
vssc_raw_card_signature_shallow_copy_const(const vssc_raw_card_signature_t *self) {

    return vssc_raw_card_signature_shallow_copy((vssc_raw_card_signature_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_signature_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_signature_init_ctx(vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_signature_cleanup_ctx(vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->signer_id);
    vsc_buffer_destroy(&self->signature);
    vsc_buffer_destroy(&self->snapshot);
    vssc_json_object_delete(self->extra_fields);
}

//
//  Create Raw Card Signature with mandatory properties.
//
static void
vssc_raw_card_signature_init_ctx_with_signature(
        vssc_raw_card_signature_t *self, vsc_str_t signer_id, vsc_data_t signature) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT(vsc_data_is_valid_and_non_empty(signature));

    self->signer_id = vsc_str_mutable_from_str(signer_id);
    self->signature = vsc_buffer_new_with_data(signature);
    self->extra_fields = vssc_json_object_new();
}

//
//  Create Raw Card Signature with mandatory properties.
//
static void
vssc_raw_card_signature_init_ctx_with_signature_disown(
        vssc_raw_card_signature_t *self, vsc_str_t signer_id, vsc_buffer_t **signature_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT_REF(signature_ref);
    VSSC_ASSERT(vsc_buffer_is_valid(*signature_ref));
    VSSC_ASSERT(vsc_buffer_len(*signature_ref) > 0);

    self->signer_id = vsc_str_mutable_from_str(signer_id);
    self->signature = *signature_ref;
    self->extra_fields = vssc_json_object_new();

    *signature_ref = NULL;
}

//
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
static void
vssc_raw_card_signature_init_ctx_with_extra_fields(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_data_t signature, const vssc_json_object_t *extra_fields) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT(vsc_data_is_valid_and_non_empty(signature));
    VSSC_ASSERT_PTR(extra_fields);

    self->signer_id = vsc_str_mutable_from_str(signer_id);
    self->signature = vsc_buffer_new_with_data(signature);

    if (!vssc_json_object_is_empty(extra_fields)) {
        vsc_str_t extra_fields_snapshot = vssc_json_object_as_str(extra_fields);
        self->snapshot = vsc_buffer_new_with_data(vsc_str_as_data(extra_fields_snapshot));
    }

    self->extra_fields = vssc_json_object_shallow_copy_const(extra_fields);
}

//
//  Create Raw Card Signature with extra fields.
//
//  Note, snapshot is taken from the extra fields.
//
static void
vssc_raw_card_signature_init_ctx_with_extra_fields_disown(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vssc_json_object_t **extra_fields_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT_REF(signature_ref);
    VSSC_ASSERT(vsc_buffer_is_valid(*signature_ref));
    VSSC_ASSERT(vsc_buffer_len(*signature_ref) > 0);
    VSSC_ASSERT_REF(extra_fields_ref);

    self->signer_id = vsc_str_mutable_from_str(signer_id);
    self->signature = *signature_ref;
    *signature_ref = NULL;

    if (!vssc_json_object_is_empty(*extra_fields_ref)) {
        vsc_str_t extra_fields_snapshot = vssc_json_object_as_str(*extra_fields_ref);
        self->snapshot = vsc_buffer_new_with_data(vsc_str_as_data(extra_fields_snapshot));
    }

    self->extra_fields = *extra_fields_ref;
    *extra_fields_ref = NULL;
}

//
//  Create raw card signature with imported values.
//
static void
vssc_raw_card_signature_init_ctx_with_imported(vssc_raw_card_signature_t *self, vsc_str_t signer_id,
        vsc_buffer_t **signature_ref, vsc_buffer_t **snapshot_ref, vssc_json_object_t **extra_fields_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(signer_id));
    VSSC_ASSERT_REF(signature_ref);

    self->signer_id = vsc_str_mutable_from_str(signer_id);
    self->signature = *signature_ref;

    *signature_ref = NULL;

    if (snapshot_ref != NULL && *snapshot_ref != NULL && extra_fields_ref != NULL && *extra_fields_ref != NULL) {
        VSSC_ASSERT(!vssc_json_object_is_empty(*extra_fields_ref));

        self->snapshot = *snapshot_ref;
        self->extra_fields = *extra_fields_ref;

        *snapshot_ref = NULL;
        *extra_fields_ref = NULL;
    } else {
        self->extra_fields = vssc_json_object_new();
    }
}

//
//  Return identifier of signer.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_signature_signer_id(const vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_mutable_as_str(self->signer_id);
}

//
//  Return signature.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_signature_signature(const vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->signature);

    return vsc_buffer_data(self->signature);
}

//
//  Return snaphot of additional data.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_signature_snapshot(const vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    if (self->snapshot) {
        return vsc_buffer_data(self->snapshot);
    } else {
        return vsc_data_empty();
    }
}

//
//  Return signed extra fields.
//
VSSC_PUBLIC const vssc_json_object_t *
vssc_raw_card_signature_extra_fields(const vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->extra_fields);

    return self->extra_fields;
}

//
//  Create raw card signature from JSON representation.
//
VSSC_PUBLIC vssc_raw_card_signature_t *
vssc_raw_card_signature_import_from_json(const vssc_json_object_t *json, vssc_error_t *error) {

    VSSC_ASSERT_PTR(json);

    vsc_buffer_t *snapshot = NULL;
    vsc_buffer_t *signature = NULL;
    vssc_json_object_t *extra_fields = NULL;

    vssc_error_t local_error;
    vssc_error_reset(&local_error);

    //
    //  Get json: signer_id
    //
    vsc_str_t signer_id = vssc_json_object_get_string_value(json, k_json_key_signer_id, &local_error);
    if (local_error.status != vssc_status_SUCCESS) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
        goto fail;
    }

    //
    //  Get json: signature
    //
    const size_t signature_len = vssc_json_object_get_binary_value_len(json, k_json_key_signature);
    if (signature_len == 0) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
        goto fail;
    }

    signature = vsc_buffer_new_with_capacity(signature_len);

    local_error.status = vssc_json_object_get_binary_value(json, k_json_key_signature, signature);
    if (local_error.status != vssc_status_SUCCESS) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
        goto fail;
    }

    //
    //  Get json: snapshot
    //
    const size_t snapshot_len = vssc_json_object_get_binary_value_len(json, k_json_key_snapshot);
    if (snapshot_len != 0) {
        snapshot = vsc_buffer_new_with_capacity(snapshot_len);

        local_error.status = vssc_json_object_get_binary_value(json, k_json_key_snapshot, snapshot);
        if (local_error.status != vssc_status_SUCCESS) {
            VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
            goto fail;
        }

        vsc_str_t snapshot_str = vsc_str_from_data(vsc_buffer_data(snapshot));
        extra_fields = vssc_json_object_parse(snapshot_str, &local_error);
        if (NULL == extra_fields) {
            VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
            goto fail;
        }
    }

    return vssc_raw_card_signature_new_with_imported(signer_id, &signature, &snapshot, &extra_fields);

fail:
    vsc_buffer_destroy(&signature);
    vsc_buffer_destroy(&snapshot);
    vssc_json_object_destroy(&extra_fields);

    return NULL;
}

//
//  Export Raw Card Signature as JSON.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_raw_card_signature_export_as_json(const vssc_raw_card_signature_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_object_t *json = vssc_json_object_new();
    vssc_json_object_add_string_value(json, k_json_key_signer_id, vssc_raw_card_signature_signer_id(self));
    vssc_json_object_add_binary_value(json, k_json_key_signature, vssc_raw_card_signature_signature(self));

    if (self->snapshot) {
        vssc_json_object_add_binary_value(json, k_json_key_snapshot, vsc_buffer_data(self->snapshot));
    }

    return json;
}
