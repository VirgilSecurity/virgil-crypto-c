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
//  A new or stored record within the Virgil Keyknox Service.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssk_keyknox_entry.h"
#include "vssk_memory.h"
#include "vssk_assert.h"
#include "vssk_keyknox_entry_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssk_keyknox_entry_init() is called.
//  Note, that context is already zeroed.
//
static void
vssk_keyknox_entry_init_ctx(vssk_keyknox_entry_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssk_keyknox_entry_cleanup_ctx(vssk_keyknox_entry_t *self);

//
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
static void
vssk_keyknox_entry_init_ctx_with(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
static void
vssk_keyknox_entry_init_ctx_with_disown(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref);

//
//  Create fully defined Keyknox entry.
//
static void
vssk_keyknox_entry_init_ctx_with_owner(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash);

//
//  Create fully defined Keyknox entry.
//
static void
vssk_keyknox_entry_init_ctx_with_owner_disown(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root,
        vsc_str_t path, vsc_str_t key, vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref,
        vsc_buffer_t **value_ref, vsc_buffer_t **hash_ref);

//
//  Return size of 'vssk_keyknox_entry_t'.
//
VSSK_PUBLIC size_t
vssk_keyknox_entry_ctx_size(void) {

    return sizeof(vssk_keyknox_entry_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init(vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));

    self->refcnt = 1;

    vssk_keyknox_entry_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSK_PUBLIC void
vssk_keyknox_entry_cleanup(vssk_keyknox_entry_t *self) {

    if (self == NULL) {
        return;
    }

    vssk_keyknox_entry_cleanup_ctx(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new(void) {

    vssk_keyknox_entry_t *self = (vssk_keyknox_entry_t *) vssk_alloc(sizeof (vssk_keyknox_entry_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_entry_init(self);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init_with(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));

    self->refcnt = 1;

    vssk_keyknox_entry_init_ctx_with(self, root, path, key, identities, meta, value, hash);
}

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with(vsc_str_t root, vsc_str_t path, vsc_str_t key, const vssc_string_list_t *identities,
        vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    vssk_keyknox_entry_t *self = (vssk_keyknox_entry_t *) vssk_alloc(sizeof (vssk_keyknox_entry_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_entry_init_with(self, root, path, key, identities, meta, value, hash);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PRIVATE void
vssk_keyknox_entry_init_with_disown(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));

    self->refcnt = 1;

    vssk_keyknox_entry_init_ctx_with_disown(self, root, path, key, identities_ref, meta_ref, value_ref, hash_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
VSSK_PRIVATE vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_disown(vsc_str_t root, vsc_str_t path, vsc_str_t key, vssc_string_list_t **identities_ref,
        vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref, vsc_buffer_t **hash_ref) {

    vssk_keyknox_entry_t *self = (vssk_keyknox_entry_t *) vssk_alloc(sizeof (vssk_keyknox_entry_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_entry_init_with_disown(self, root, path, key, identities_ref, meta_ref, value_ref, hash_ref);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined Keyknox entry.
//
VSSK_PUBLIC void
vssk_keyknox_entry_init_with_owner(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));

    self->refcnt = 1;

    vssk_keyknox_entry_init_ctx_with_owner(self, owner, root, path, key, identities, meta, value, hash);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined Keyknox entry.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_owner(vsc_str_t owner, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    vssk_keyknox_entry_t *self = (vssk_keyknox_entry_t *) vssk_alloc(sizeof (vssk_keyknox_entry_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_entry_init_with_owner(self, owner, root, path, key, identities, meta, value, hash);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create fully defined Keyknox entry.
//
VSSK_PRIVATE void
vssk_keyknox_entry_init_with_owner_disown(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref) {

    VSSK_ASSERT_PTR(self);

    vssk_zeroize(self, sizeof(vssk_keyknox_entry_t));

    self->refcnt = 1;

    vssk_keyknox_entry_init_ctx_with_owner_disown(self, owner, root, path, key, identities_ref, meta_ref, value_ref, hash_ref);
}

//
//  Allocate class context and perform it's initialization.
//  Create fully defined Keyknox entry.
//
VSSK_PRIVATE vssk_keyknox_entry_t *
vssk_keyknox_entry_new_with_owner_disown(vsc_str_t owner, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref) {

    vssk_keyknox_entry_t *self = (vssk_keyknox_entry_t *) vssk_alloc(sizeof (vssk_keyknox_entry_t));
    VSSK_ASSERT_ALLOC(self);

    vssk_keyknox_entry_init_with_owner_disown(self, owner, root, path, key, identities_ref, meta_ref, value_ref, hash_ref);

    self->self_dealloc_cb = vssk_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSK_PUBLIC void
vssk_keyknox_entry_delete(const vssk_keyknox_entry_t *self) {

    vssk_keyknox_entry_t *local_self = (vssk_keyknox_entry_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSK_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSK_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssk_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssk_keyknox_entry_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssk_keyknox_entry_new ()'.
//
VSSK_PUBLIC void
vssk_keyknox_entry_destroy(vssk_keyknox_entry_t **self_ref) {

    VSSK_ASSERT_PTR(self_ref);

    vssk_keyknox_entry_t *self = *self_ref;
    *self_ref = NULL;

    vssk_keyknox_entry_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSK_PUBLIC vssk_keyknox_entry_t *
vssk_keyknox_entry_shallow_copy(vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);

    #if defined(VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSK_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSK_PUBLIC const vssk_keyknox_entry_t *
vssk_keyknox_entry_shallow_copy_const(const vssk_keyknox_entry_t *self) {

    return vssk_keyknox_entry_shallow_copy((vssk_keyknox_entry_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssk_keyknox_entry_init() is called.
//  Note, that context is already zeroed.
//
static void
vssk_keyknox_entry_init_ctx(vssk_keyknox_entry_t *self) {

    VSSK_UNUSED(self);
    VSSK_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssk_keyknox_entry_cleanup_ctx(vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->owner);
    vsc_str_mutable_release(&self->root);
    vsc_str_mutable_release(&self->path);
    vsc_str_mutable_release(&self->key);

    vsc_buffer_destroy(&self->meta);
    vsc_buffer_destroy(&self->value);
    vsc_buffer_destroy(&self->hash);

    vssc_string_list_delete(self->identities);
}

//
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
static void
vssk_keyknox_entry_init_ctx_with(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    VSSK_ASSERT_PTR(self);

    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(key));

    VSSK_ASSERT_PTR(identities);
    VSSK_ASSERT(vssc_string_list_has_item(identities));

    VSSK_ASSERT(vsc_data_is_valid_and_non_empty(meta));
    VSSK_ASSERT(vsc_data_is_valid_and_non_empty(value));
    VSSK_ASSERT(vsc_data_is_valid(hash));

    self->root = vsc_str_mutable_from_str(root);
    self->path = vsc_str_mutable_from_str(path);
    self->key = vsc_str_mutable_from_str(key);

    self->identities = vssc_string_list_shallow_copy_const(identities);
    self->meta = vsc_buffer_new_with_data(meta);
    self->value = vsc_buffer_new_with_data(value);

    if (!vsc_data_is_empty(hash)) {
        self->hash = vsc_buffer_new_with_data(hash);
    }
}

//
//  Create Keyknox entry without "owner".
//  Suitable for the push operation to the the Keyknox Service.
//
static void
vssk_keyknox_entry_init_ctx_with_disown(vssk_keyknox_entry_t *self, vsc_str_t root, vsc_str_t path, vsc_str_t key,
        vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref, vsc_buffer_t **value_ref,
        vsc_buffer_t **hash_ref) {

    VSSK_ASSERT_PTR(self);

    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(key));

    VSSK_ASSERT_REF(identities_ref);
    VSSK_ASSERT(vssc_string_list_has_item(*identities_ref));

    VSSK_ASSERT_REF(meta_ref);
    VSSK_ASSERT_REF(value_ref);

    VSSK_ASSERT(vsc_buffer_is_valid_and_non_empty(*meta_ref));
    VSSK_ASSERT(vsc_buffer_is_valid_and_non_empty(*value_ref));

    self->root = vsc_str_mutable_from_str(root);
    self->path = vsc_str_mutable_from_str(path);
    self->key = vsc_str_mutable_from_str(key);

    self->identities = *identities_ref;
    *identities_ref = NULL;

    self->meta = *meta_ref;
    self->value = *value_ref;

    *meta_ref = NULL;
    *value_ref = NULL;

    if (hash_ref != NULL && vsc_buffer_is_valid_and_non_empty(*hash_ref)) {
        self->hash = *hash_ref;
        *hash_ref = NULL;
    }
}

//
//  Create fully defined Keyknox entry.
//
static void
vssk_keyknox_entry_init_ctx_with_owner(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root, vsc_str_t path,
        vsc_str_t key, const vssc_string_list_t *identities, vsc_data_t meta, vsc_data_t value, vsc_data_t hash) {

    VSSK_ASSERT_PTR(self);

    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(owner));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(key));

    VSSK_ASSERT_PTR(identities);
    VSSK_ASSERT(vssc_string_list_has_item(identities));

    VSSK_ASSERT(vsc_data_is_valid_and_non_empty(meta));
    VSSK_ASSERT(vsc_data_is_valid_and_non_empty(value));
    VSSK_ASSERT(vsc_data_is_valid_and_non_empty(hash));

    self->owner = vsc_str_mutable_from_str(owner);
    self->root = vsc_str_mutable_from_str(root);
    self->path = vsc_str_mutable_from_str(path);
    self->key = vsc_str_mutable_from_str(key);

    self->identities = vssc_string_list_shallow_copy_const(identities);
    self->meta = vsc_buffer_new_with_data(meta);
    self->value = vsc_buffer_new_with_data(value);
    self->hash = vsc_buffer_new_with_data(hash);
}

//
//  Create fully defined Keyknox entry.
//
static void
vssk_keyknox_entry_init_ctx_with_owner_disown(vssk_keyknox_entry_t *self, vsc_str_t owner, vsc_str_t root,
        vsc_str_t path, vsc_str_t key, vssc_string_list_t **identities_ref, vsc_buffer_t **meta_ref,
        vsc_buffer_t **value_ref, vsc_buffer_t **hash_ref) {

    VSSK_ASSERT_PTR(self);

    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(owner));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(root));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(path));
    VSSK_ASSERT(vsc_str_is_valid_and_non_empty(key));

    VSSK_ASSERT_REF(identities_ref);
    VSSK_ASSERT(vssc_string_list_has_item(*identities_ref));

    VSSK_ASSERT_REF(meta_ref);
    VSSK_ASSERT_REF(value_ref);

    VSSK_ASSERT(vsc_buffer_is_valid_and_non_empty(*meta_ref));
    VSSK_ASSERT(vsc_buffer_is_valid_and_non_empty(*value_ref));
    VSSK_ASSERT(vsc_buffer_is_valid_and_non_empty(*hash_ref));

    self->owner = vsc_str_mutable_from_str(owner);
    self->root = vsc_str_mutable_from_str(root);
    self->path = vsc_str_mutable_from_str(path);
    self->key = vsc_str_mutable_from_str(key);

    self->identities = *identities_ref;
    *identities_ref = NULL;

    self->meta = *meta_ref;
    self->value = *value_ref;
    self->hash = *hash_ref;

    *meta_ref = NULL;
    *value_ref = NULL;
    *hash_ref = NULL;
}

//
//  Return owner.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_owner(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->owner)) {
        return vsc_str_mutable_as_str(self->owner);
    } else {
        return vsc_str_empty();
    }
}

//
//  Return root path.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_root(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_mutable_is_valid(self->root));

    return vsc_str_mutable_as_str(self->root);
}

//
//  Return second path.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_path(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_mutable_is_valid(self->path));

    return vsc_str_mutable_as_str(self->path);
}

//
//  Return key.
//
VSSK_PUBLIC vsc_str_t
vssk_keyknox_entry_key(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT(vsc_str_mutable_is_valid(self->key));

    return vsc_str_mutable_as_str(self->key);
}

//
//  Return list of users that have access to the entry.
//
VSSK_PUBLIC const vssc_string_list_t *
vssk_keyknox_entry_identities(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT_PTR(self->identities);

    return self->identities;
}

//
//  Return meta.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_meta(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT_PTR(self->meta);

    return vsc_buffer_data(self->meta);
}

//
//  Return value.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_value(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);
    VSSK_ASSERT_PTR(self->value);

    return vsc_buffer_data(self->value);
}

//
//  Return hash.
//
VSSK_PUBLIC vsc_data_t
vssk_keyknox_entry_hash(const vssk_keyknox_entry_t *self) {

    VSSK_ASSERT_PTR(self);

    if (self->hash != NULL) {
        return vsc_buffer_data(self->hash);
    } else {
        return vsc_data_empty();
    }
}
