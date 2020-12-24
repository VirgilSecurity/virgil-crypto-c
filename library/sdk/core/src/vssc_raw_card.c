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
//  Represent model in binary form which can have signatures and corresponds to Virgil Cards Service model.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_raw_card.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_raw_card_defs.h"
#include "vssc_json_object.h"
#include "vssc_json_object_private.h"
#include "vssc_json_array_private.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_init_ctx(vssc_raw_card_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_cleanup_ctx(vssc_raw_card_t *self);

//
//  Create raw card with mandatory info.
//
static void
vssc_raw_card_init_ctx_with(vssc_raw_card_t *self, vsc_str_t identity, vsc_data_t public_key, size_t created_at);

//
//  Create raw card with mandatory info.
//
static void
vssc_raw_card_init_ctx_with_disown(vssc_raw_card_t *self, vsc_str_t identity, vsc_buffer_t **public_key_ref,
        size_t created_at);

//
//  Perform initialization of pre-allocated context.
//  Create raw card with imported values.
//
static void
vssc_raw_card_init_with_imported(vssc_raw_card_t *self, vssc_json_object_t **content_ref,
        vsc_buffer_t **content_snapshot_ref, vsc_buffer_t **public_key_ref,
        vssc_raw_card_signature_list_t **signatures_ref);

//
//  Create raw card with imported values.
//
static void
vssc_raw_card_init_ctx_with_imported(vssc_raw_card_t *self, vssc_json_object_t **content_ref,
        vsc_buffer_t **content_snapshot_ref, vsc_buffer_t **public_key_ref,
        vssc_raw_card_signature_list_t **signatures_ref);

//
//  Allocate class context and perform it's initialization.
//  Create raw card with imported values.
//
static vssc_raw_card_t *
vssc_raw_card_new_with_imported(vssc_json_object_t **content_ref, vsc_buffer_t **content_snapshot_ref,
        vsc_buffer_t **public_key_ref, vssc_raw_card_signature_list_t **signatures_ref);

//
//  Default Virgil Card version.
//
static const char k_default_version_chars[] = "5.0";

//
//  Default Virgil Card version.
//
static const vsc_str_t k_default_version = {
    k_default_version_chars,
    sizeof(k_default_version_chars) - 1
};

//
//  JSON key: public_key
//
static const char k_json_key_public_key_chars[] = "public_key";

//
//  JSON key: public_key
//
static const vsc_str_t k_json_key_public_key = {
    k_json_key_public_key_chars,
    sizeof(k_json_key_public_key_chars) - 1
};

//
//  JSON key: identity
//
static const char k_json_key_identity_chars[] = "identity";

//
//  JSON key: identity
//
static const vsc_str_t k_json_key_identity = {
    k_json_key_identity_chars,
    sizeof(k_json_key_identity_chars) - 1
};

//
//  JSON key: card_type
//
static const char k_json_key_card_type_chars[] = "card_type";

//
//  JSON key: card_type
//
static const vsc_str_t k_json_key_card_type = {
    k_json_key_card_type_chars,
    sizeof(k_json_key_card_type_chars) - 1
};

//
//  JSON key: previous_card_id
//
static const char k_json_key_previous_card_id_chars[] = "previous_card_id";

//
//  JSON key: previous_card_id
//
static const vsc_str_t k_json_key_previous_card_id = {
    k_json_key_previous_card_id_chars,
    sizeof(k_json_key_previous_card_id_chars) - 1
};

//
//  JSON key: version
//
static const char k_json_key_version_chars[] = "version";

//
//  JSON key: version
//
static const vsc_str_t k_json_key_version = {
    k_json_key_version_chars,
    sizeof(k_json_key_version_chars) - 1
};

//
//  JSON key: created_at
//
static const char k_json_key_created_at_chars[] = "created_at";

//
//  JSON key: created_at
//
static const vsc_str_t k_json_key_created_at = {
    k_json_key_created_at_chars,
    sizeof(k_json_key_created_at_chars) - 1
};

//
//  JSON key: content_snapshot
//
static const char k_json_key_content_snapshot_chars[] = "content_snapshot";

//
//  JSON key: content_snapshot
//
static const vsc_str_t k_json_key_content_snapshot = {
    k_json_key_content_snapshot_chars,
    sizeof(k_json_key_content_snapshot_chars) - 1
};

//
//  JSON key: signatures
//
static const char k_json_key_signatures_chars[] = "signatures";

//
//  JSON key: signatures
//
static const vsc_str_t k_json_key_signatures = {
    k_json_key_signatures_chars,
    sizeof(k_json_key_signatures_chars) - 1
};

//
//  Return size of 'vssc_raw_card_t'.
//
VSSC_PUBLIC size_t
vssc_raw_card_ctx_size(void) {

    return sizeof(vssc_raw_card_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_raw_card_init(vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_t));

    self->refcnt = 1;

    vssc_raw_card_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_raw_card_cleanup(vssc_raw_card_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_raw_card_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_new(void) {

    vssc_raw_card_t *self = (vssc_raw_card_t *) vssc_alloc(sizeof (vssc_raw_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create raw card with mandatory info.
//
VSSC_PUBLIC void
vssc_raw_card_init_with(vssc_raw_card_t *self, vsc_str_t identity, vsc_data_t public_key, size_t created_at) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_t));

    self->refcnt = 1;

    vssc_raw_card_init_ctx_with(self, identity, public_key, created_at);
}

//
//  Allocate class context and perform it's initialization.
//  Create raw card with mandatory info.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_new_with(vsc_str_t identity, vsc_data_t public_key, size_t created_at) {

    vssc_raw_card_t *self = (vssc_raw_card_t *) vssc_alloc(sizeof (vssc_raw_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_init_with(self, identity, public_key, created_at);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create raw card with mandatory info.
//
VSSC_PRIVATE void
vssc_raw_card_init_with_disown(vssc_raw_card_t *self, vsc_str_t identity, vsc_buffer_t **public_key_ref,
        size_t created_at) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_t));

    self->refcnt = 1;

    vssc_raw_card_init_ctx_with_disown(self, identity, public_key_ref, created_at);
}

//
//  Allocate class context and perform it's initialization.
//  Create raw card with mandatory info.
//
VSSC_PRIVATE vssc_raw_card_t *
vssc_raw_card_new_with_disown(vsc_str_t identity, vsc_buffer_t **public_key_ref, size_t created_at) {

    vssc_raw_card_t *self = (vssc_raw_card_t *) vssc_alloc(sizeof (vssc_raw_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_init_with_disown(self, identity, public_key_ref, created_at);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create raw card with imported values.
//
static void
vssc_raw_card_init_with_imported(vssc_raw_card_t *self, vssc_json_object_t **content_ref,
        vsc_buffer_t **content_snapshot_ref, vsc_buffer_t **public_key_ref,
        vssc_raw_card_signature_list_t **signatures_ref) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_raw_card_t));

    self->refcnt = 1;

    vssc_raw_card_init_ctx_with_imported(self, content_ref, content_snapshot_ref, public_key_ref, signatures_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create raw card with imported values.
//
static vssc_raw_card_t *
vssc_raw_card_new_with_imported(vssc_json_object_t **content_ref, vsc_buffer_t **content_snapshot_ref,
        vsc_buffer_t **public_key_ref, vssc_raw_card_signature_list_t **signatures_ref) {

    vssc_raw_card_t *self = (vssc_raw_card_t *) vssc_alloc(sizeof (vssc_raw_card_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_raw_card_init_with_imported(self, content_ref, content_snapshot_ref, public_key_ref, signatures_ref);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_raw_card_delete(const vssc_raw_card_t *self) {

    vssc_raw_card_t *local_self = (vssc_raw_card_t *)self;

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

    vssc_raw_card_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_raw_card_new ()'.
//
VSSC_PUBLIC void
vssc_raw_card_destroy(vssc_raw_card_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_raw_card_t *self = *self_ref;
    *self_ref = NULL;

    vssc_raw_card_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_shallow_copy(vssc_raw_card_t *self) {

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
VSSC_PUBLIC const vssc_raw_card_t *
vssc_raw_card_shallow_copy_const(const vssc_raw_card_t *self) {

    return vssc_raw_card_shallow_copy((vssc_raw_card_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_raw_card_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_raw_card_init_ctx(vssc_raw_card_t *self) {

    VSSC_UNUSED(self);
    VSSC_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_raw_card_cleanup_ctx(vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_object_destroy(&self->content);
    vsc_buffer_destroy(&self->content_snapshot);
    vssc_raw_card_signature_list_destroy(&self->signatures);
    vsc_buffer_destroy(&self->public_key);
}

//
//  Create raw card with mandatory info.
//
static void
vssc_raw_card_init_ctx_with(vssc_raw_card_t *self, vsc_str_t identity, vsc_data_t public_key, size_t created_at) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT(vsc_data_is_valid(public_key));

    vsc_buffer_t *public_key_buf = NULL;
    if (!vsc_data_is_empty(public_key)) {
        public_key_buf = vsc_buffer_new_with_data(public_key);
    }

    vssc_raw_card_init_ctx_with_disown(self, identity, &public_key_buf, created_at);
}

//
//  Create raw card with mandatory info.
//
static void
vssc_raw_card_init_ctx_with_disown(
        vssc_raw_card_t *self, vsc_str_t identity, vsc_buffer_t **public_key_ref, size_t created_at) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));
    VSSC_ASSERT(0 < created_at && created_at < INT_MAX);

    self->is_outdated = false;
    self->signatures = vssc_raw_card_signature_list_new();

    if (public_key_ref != NULL && *public_key_ref != NULL) {
        VSSC_ASSERT(vsc_buffer_is_valid(*public_key_ref));
        self->public_key = *public_key_ref;
        *public_key_ref = NULL;
    }

    //
    //  Build content.
    //
    self->content = vssc_json_object_new();
    vssc_json_object_add_int_value(self->content, k_json_key_created_at, (int)created_at);
    vssc_json_object_add_string_value(self->content, k_json_key_identity, identity);
    vssc_json_object_add_string_value(self->content, k_json_key_version, k_default_version);

    if (self->public_key) {
        vssc_json_object_add_binary_value(self->content, k_json_key_public_key, vsc_buffer_data(self->public_key));
    }

    //
    //  Build content-snapshot.
    //
    vsc_str_t content_snapshot = vssc_json_object_as_str(self->content);
    self->content_snapshot = vsc_buffer_new_with_data(vsc_str_as_data(content_snapshot));
}

//
//  Create raw card with imported values.
//
static void
vssc_raw_card_init_ctx_with_imported(vssc_raw_card_t *self, vssc_json_object_t **content_ref,
        vsc_buffer_t **content_snapshot_ref, vsc_buffer_t **public_key_ref,
        vssc_raw_card_signature_list_t **signatures_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(content_ref);
    VSSC_ASSERT_REF(content_snapshot_ref);
    VSSC_ASSERT_REF(public_key_ref);
    VSSC_ASSERT_REF(signatures_ref);

    self->content = *content_ref;
    self->content_snapshot = *content_snapshot_ref;
    self->public_key = *public_key_ref;
    self->signatures = *signatures_ref;

    *content_ref = NULL;
    *content_snapshot_ref = NULL;
    *public_key_ref = NULL;
    *signatures_ref = NULL;
}

//
//  Create raw card from JSON representation.
//
VSSC_PUBLIC vssc_raw_card_t *
vssc_raw_card_import_from_json(const vssc_json_object_t *json, vssc_error_t *error) {

    VSSC_ASSERT_PTR(json);

    vssc_error_t local_error;
    vssc_error_reset(&local_error);

    vssc_json_object_t *content_json = NULL;
    vssc_json_array_t *signatures_json = NULL;
    vssc_json_object_t *signature_json = NULL;
    vsc_buffer_t *content_snapshot = NULL;
    vsc_buffer_t *public_key = NULL;
    vssc_raw_card_signature_list_t *signatures = NULL;
    vssc_raw_card_signature_t *signature = NULL;

    //
    //  Import content-snapshot.
    //
    const size_t content_snapshot_len = vssc_json_object_get_binary_value_len(json, k_json_key_content_snapshot);
    if (content_snapshot_len == 0) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    content_snapshot = vsc_buffer_new_with_capacity(content_snapshot_len);

    local_error.status = vssc_json_object_get_binary_value(json, k_json_key_content_snapshot, content_snapshot);
    if (local_error.status != vssc_status_SUCCESS) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    vsc_str_t content_snapshot_str = vsc_str_from_data(vsc_buffer_data(content_snapshot));
    content_json = vssc_json_object_parse(content_snapshot_str, &local_error);
    if (NULL == content_json) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    //
    //  Validate content-snapshot fileds.
    //

    vsc_str_t version_str = vssc_json_object_get_string_value(content_json, k_json_key_version, &local_error);
    if (vsc_str_is_empty(version_str)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    if (!vsc_str_equal(version_str, k_default_version)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_CARD_VERSION_IS_NOT_SUPPORTED);
        goto fail;
    }

    const size_t public_key_len = vssc_json_object_get_binary_value_len(content_json, k_json_key_public_key);
    if (public_key_len == 0) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    public_key = vsc_buffer_new_with_capacity(public_key_len);
    local_error.status = vssc_json_object_get_binary_value(content_json, k_json_key_public_key, public_key);
    if (local_error.status != vssc_status_SUCCESS) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    vsc_str_t identity_str = vssc_json_object_get_string_value(content_json, k_json_key_identity, &local_error);
    if (vsc_str_is_empty(identity_str)) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    const int created_at = vssc_json_object_get_int_value(content_json, k_json_key_created_at, &local_error);
    if (created_at <= 0) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }

    vsc_str_t card_type_str = vssc_json_object_get_string_value(content_json, k_json_key_card_type, &local_error);
    if (vssc_error_status(&local_error) == vssc_status_JSON_VALUE_TYPE_MISMATCH) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }
    VSSC_UNUSED(card_type_str);

    vsc_str_t previous_card_id_str =
            vssc_json_object_get_string_value(content_json, k_json_key_previous_card_id, &local_error);
    if (vssc_error_status(&local_error) == vssc_status_JSON_VALUE_TYPE_MISMATCH) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_CONTENT_PARSE_FAILED);
        goto fail;
    }
    VSSC_UNUSED(previous_card_id_str);

    //
    //  Import signatures.
    //
    signatures_json = vssc_json_object_get_array_value(json, k_json_key_signatures, &local_error);
    if (local_error.status == vssc_status_JSON_VALUE_TYPE_MISMATCH) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
        goto fail;
    }

    signatures = vssc_raw_card_signature_list_new();
    for (size_t i = 0; i < vssc_json_array_count(signatures_json); ++i) {
        signature_json = vssc_json_array_get_object_value(signatures_json, i, &local_error);
        if (NULL == signature_json) {
            VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
            goto fail;
        }

        signature = vssc_raw_card_signature_import_from_json(signature_json, &local_error);
        vssc_json_object_destroy(&signature_json);

        if (NULL == signature) {
            VSSC_ERROR_SAFE_UPDATE(error, vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED);
            goto fail;
        }


        vssc_raw_card_signature_list_add_disown(signatures, &signature);
    }

    vssc_json_array_destroy(&signatures_json);

    //
    //  Create Raw Card
    //
    return vssc_raw_card_new_with_imported(&content_json, &content_snapshot, &public_key, &signatures);

fail:
    vssc_json_object_destroy(&content_json);
    vssc_json_array_destroy(&signatures_json);
    vsc_buffer_destroy(&content_snapshot);
    vsc_buffer_destroy(&public_key);
    vssc_raw_card_signature_list_destroy(&signatures);

    return NULL;
}

//
//  Export Raw Card as JSON.
//
VSSC_PUBLIC vssc_json_object_t *
vssc_raw_card_export_as_json(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_json_array_t *json_signatures = vssc_json_array_new();
    for (const vssc_raw_card_signature_list_t *it = self->signatures;
            (it != NULL) && vssc_raw_card_signature_list_has_item(it); it = vssc_raw_card_signature_list_next(it)) {
        const vssc_raw_card_signature_t *signature = vssc_raw_card_signature_list_item(it);
        vssc_json_object_t *json_signature = vssc_raw_card_signature_export_as_json(signature);
        vssc_json_array_add_object_value_disown(json_signatures, &json_signature);
    }

    vssc_json_object_t *json = vssc_json_object_new();
    vssc_json_object_add_binary_value(json, k_json_key_content_snapshot, vssc_raw_card_content_snapshot(self));
    vssc_json_object_add_array_value_disown(json, k_json_key_signatures, &json_signatures);

    return json;
}

//
//  Set optional previous card identifier.
//
//  Note, previous card identity and the current one should be the same.
//
VSSC_PUBLIC void
vssc_raw_card_set_previous_card_id(vssc_raw_card_t *self, vsc_str_t previous_card_id) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(previous_card_id));

    vssc_json_object_add_string_value(self->content, k_json_key_previous_card_id, previous_card_id);
    vssc_raw_card_invalidate_content_snapshot(self);
}

//
//  Set optional card type.
//
VSSC_PUBLIC void
vssc_raw_card_set_card_type(vssc_raw_card_t *self, vsc_str_t card_type) {

    vssc_json_object_add_string_value(self->content, k_json_key_card_type, card_type);
    vssc_raw_card_invalidate_content_snapshot(self);
}

//
//  Add new signature.
//
VSSC_PUBLIC void
vssc_raw_card_add_signature(vssc_raw_card_t *self, const vssc_raw_card_signature_t *signature) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->signatures);
    VSSC_ASSERT_PTR(signature);

    vssc_raw_card_signature_list_add(self->signatures, signature);
}

//
//  Add new signature.
//
VSSC_PRIVATE void
vssc_raw_card_add_signature_disown(vssc_raw_card_t *self, vssc_raw_card_signature_t **signature_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->signatures);
    VSSC_ASSERT_REF(signature_ref);

    vssc_raw_card_signature_list_add_disown(self->signatures, signature_ref);
}

//
//  Set whether a Card is outdated or not.
//
VSSC_PUBLIC void
vssc_raw_card_set_is_outdated(vssc_raw_card_t *self, bool is_outdated) {

    VSSC_ASSERT_PTR(self);

    self->is_outdated = is_outdated;
}

//
//  Return version of Card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_version(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);

    vsc_str_t result = vssc_json_object_get_string_value(self->content, k_json_key_version, NULL);

    return result;
}

//
//  Return identity of Card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_identity(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);

    vsc_str_t result = vssc_json_object_get_string_value(self->content, k_json_key_identity, NULL);

    return result;
}

//
//  Return Public Key data of Card.
//
//  Note, public key can be empty.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_public_key(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);

    if (self->public_key) {
        return vsc_buffer_data(self->public_key);
    } else {
        return vsc_data_empty();
    }
}

//
//  Return date of Card creation.
//
VSSC_PUBLIC size_t
vssc_raw_card_created_at(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);

    const int result = vssc_json_object_get_int_value(self->content, k_json_key_created_at, NULL);
    VSSC_ASSERT(result > 0);

    return (size_t)result;
}

//
//  Return whether Card is outdated or not.
//
VSSC_PUBLIC bool
vssc_raw_card_is_outdated(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->is_outdated;
}

//
//  Return identifier of previous Card with same identity.
//
//  Note, return empty string if there is no previous card.
//
VSSC_PUBLIC vsc_str_t
vssc_raw_card_previous_card_id(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);

    vsc_str_t result = vssc_json_object_get_string_value(self->content, k_json_key_previous_card_id, NULL);

    return result;
}

//
//  Return Card's content snapshot.
//
VSSC_PUBLIC vsc_data_t
vssc_raw_card_content_snapshot(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content);
    VSSC_ASSERT_PTR(self->content_snapshot);

    if (vsc_buffer_is_empty(self->content_snapshot)) {
        vsc_str_t content_snapshot = vssc_json_object_as_str(self->content);
        vsc_buffer_append_data(self->content_snapshot, vsc_str_as_data(content_snapshot));
    }

    return vsc_buffer_data(self->content_snapshot);
}

//
//  Return Card's signatures.
//
VSSC_PUBLIC const vssc_raw_card_signature_list_t *
vssc_raw_card_signatures(const vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->signatures);

    return self->signatures;
}

//
//  This method invalidates content snapshot.
//  It should be called when content is modified.
//
VSSC_PUBLIC void
vssc_raw_card_invalidate_content_snapshot(vssc_raw_card_t *self) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(self->content_snapshot);

    vsc_buffer_reset(self->content_snapshot);
}
