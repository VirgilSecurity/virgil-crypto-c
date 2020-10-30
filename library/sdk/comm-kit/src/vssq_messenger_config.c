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
//  Contains messenger configuration.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_config.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_config_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_config_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_config_init_ctx(vssq_messenger_config_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_config_cleanup_ctx(vssq_messenger_config_t *self);

//
//  Create object with required fields.
//
static void
vssq_messenger_config_init_ctx_with(vssq_messenger_config_t *self, vsc_str_t base_url, vsc_str_t ejabberd_url);

VSSQ_PUBLIC const char vssq_messenger_config_k_base_url_virgil_chars[] = "https://messenger.virgilsecurity.com";

VSSQ_PUBLIC const vsc_str_t vssq_messenger_config_k_base_url_virgil = {
    vssq_messenger_config_k_base_url_virgil_chars,
    sizeof(vssq_messenger_config_k_base_url_virgil_chars) - 1
};

VSSQ_PUBLIC const char vssq_messenger_config_k_ejabberd_url_virgil_chars[] = "xmpp.virgilsecurity.com";

VSSQ_PUBLIC const vsc_str_t vssq_messenger_config_k_ejabberd_url_virgil = {
    vssq_messenger_config_k_ejabberd_url_virgil_chars,
    sizeof(vssq_messenger_config_k_ejabberd_url_virgil_chars) - 1
};

//
//  Return size of 'vssq_messenger_config_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_config_ctx_size(void) {

    return sizeof(vssq_messenger_config_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_config_init(vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_config_t));

    self->refcnt = 1;

    vssq_messenger_config_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_config_cleanup(vssq_messenger_config_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_config_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_config_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_new(void) {

    vssq_messenger_config_t *self = (vssq_messenger_config_t *) vssq_alloc(sizeof (vssq_messenger_config_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_config_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create object with required fields.
//
VSSQ_PUBLIC void
vssq_messenger_config_init_with(vssq_messenger_config_t *self, vsc_str_t base_url, vsc_str_t ejabberd_url) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_config_t));

    self->refcnt = 1;

    vssq_messenger_config_init_ctx_with(self, base_url, ejabberd_url);
}

//
//  Allocate class context and perform it's initialization.
//  Create object with required fields.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_new_with(vsc_str_t base_url, vsc_str_t ejabberd_url) {

    vssq_messenger_config_t *self = (vssq_messenger_config_t *) vssq_alloc(sizeof (vssq_messenger_config_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_config_init_with(self, base_url, ejabberd_url);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_config_delete(const vssq_messenger_config_t *self) {

    vssq_messenger_config_t *local_self = (vssq_messenger_config_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSQ_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSQ_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssq_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssq_messenger_config_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_config_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_config_destroy(vssq_messenger_config_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_config_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_config_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_config_t *
vssq_messenger_config_shallow_copy(vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_config_t *
vssq_messenger_config_shallow_copy_const(const vssq_messenger_config_t *self) {

    return vssq_messenger_config_shallow_copy((vssq_messenger_config_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_config_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_config_init_ctx(vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_config_cleanup_ctx(vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    vsc_str_mutable_release(&self->base_url);
    vsc_str_mutable_release(&self->ejabberd_url);
    vsc_str_mutable_release(&self->ca_bundle);
}

//
//  Create object with required fields.
//
static void
vssq_messenger_config_init_ctx_with(vssq_messenger_config_t *self, vsc_str_t base_url, vsc_str_t ejabberd_url) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(base_url));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(ejabberd_url));

    self->base_url = vsc_str_mutable_from_str(base_url);
    self->ejabberd_url = vsc_str_mutable_from_str(ejabberd_url);
}

//
//  Set path to the custom CA bundle.
//
VSSQ_PUBLIC void
vssq_messenger_config_set_ca_bundle(vssq_messenger_config_t *self, vsc_str_t ca_bundle) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(ca_bundle));

    vsc_str_mutable_release(&self->ca_bundle);

    self->ca_bundle = vsc_str_mutable_from_str(ca_bundle);
}

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_base_url(const vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->base_url)) {
        return vsc_str_mutable_as_str(self->base_url);
    } else {
        return vssq_messenger_config_k_base_url_virgil;
    }
}

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_ejabberd_url(const vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->ejabberd_url)) {
        return vsc_str_mutable_as_str(self->ejabberd_url);
    } else {
        return vssq_messenger_config_k_ejabberd_url_virgil;
    }
}

VSSQ_PUBLIC vsc_str_t
vssq_messenger_config_ca_bundle(const vssq_messenger_config_t *self) {

    VSSQ_ASSERT_PTR(self);

    if (vsc_str_mutable_is_valid(self->ca_bundle)) {
        return vsc_str_mutable_as_str(self->ca_bundle);
    } else {
        return vsc_str_empty();
    }
}
