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
//  Entrypoint to the messenger user management, authentication and encryption.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_private.h"
#include "vssq_messenger_defs.h"
#include "vssq_messenger_auth.h"

#include <virgil/sdk/core/vssc_card_client.h>
#include <virgil/sdk/core/vssc_card_manager.h>
#include <virgil/sdk/core/private/vssc_key_handler_list_private.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_init_ctx(vssq_messenger_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cleanup_ctx(vssq_messenger_t *self);

//
//  Initialze messenger with a custom config.
//
static void
vssq_messenger_init_ctx_with_config(vssq_messenger_t *self, const vssq_messenger_config_t *config);

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_did_setup_random(vssq_messenger_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_did_release_random(vssq_messenger_t *self);

//
//  Return size of 'vssq_messenger_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_ctx_size(void) {

    return sizeof(vssq_messenger_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_init(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_t));

    self->refcnt = 1;

    vssq_messenger_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cleanup(vssq_messenger_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_release_random(self);

    vssq_messenger_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_new(void) {

    vssq_messenger_t *self = (vssq_messenger_t *) vssq_alloc(sizeof (vssq_messenger_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Initialze messenger with a custom config.
//
VSSQ_PUBLIC void
vssq_messenger_init_with_config(vssq_messenger_t *self, const vssq_messenger_config_t *config) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_t));

    self->refcnt = 1;

    vssq_messenger_init_ctx_with_config(self, config);
}

//
//  Allocate class context and perform it's initialization.
//  Initialze messenger with a custom config.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_new_with_config(const vssq_messenger_config_t *config) {

    vssq_messenger_t *self = (vssq_messenger_t *) vssq_alloc(sizeof (vssq_messenger_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_init_with_config(self, config);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_delete(const vssq_messenger_t *self) {

    vssq_messenger_t *local_self = (vssq_messenger_t *)self;

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

    vssq_messenger_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_destroy(vssq_messenger_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_t *
vssq_messenger_shallow_copy(vssq_messenger_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_t *
vssq_messenger_shallow_copy_const(const vssq_messenger_t *self) {

    return vssq_messenger_shallow_copy((vssq_messenger_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_use_random(vssq_messenger_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);

    vssq_messenger_did_setup_random(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_take_random(vssq_messenger_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;

    vssq_messenger_did_setup_random(self);
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_release_random(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);

    vssq_messenger_did_release_random(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_init_ctx(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    self->config = vssq_messenger_config_new();
    self->auth = vssq_messenger_auth_new_with_config(self->config);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cleanup_ctx(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_delete(self->random);
    vssq_messenger_config_delete(self->config);
    vssq_messenger_auth_delete(self->auth);
    vssc_key_handler_list_delete(self->cards_cache);
}

//
//  Initialze messenger with a custom config.
//
static void
vssq_messenger_init_ctx_with_config(vssq_messenger_t *self, const vssq_messenger_config_t *config) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(config);

    self->config = vssq_messenger_config_shallow_copy_const(config);
    self->auth = vssq_messenger_auth_new_with_config(self->config);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vssq_messenger_did_setup_random(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_auth_release_random(self->auth);
    vssq_messenger_auth_use_random(self->auth, self->random);
}

//
//  This method is called when interface 'random' was released.
//
static void
vssq_messenger_did_release_random(vssq_messenger_t *self) {

    vssq_messenger_auth_release_random(self->auth);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_setup_defaults(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_setup_defaults(self->auth);
}

//
//  Register a new user with a given name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_register(vssq_messenger_t *self, vsc_str_t username) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));

    return vssq_messenger_auth_register(self->auth, username);
}

//
//  Authenticate a user with a given credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_authenticate(vssq_messenger_t *self, const vssq_messenger_creds_t *creds) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(creds);

    return vssq_messenger_auth_authenticate(self->auth, creds);
}

//
//  Return true if user credentials are defined.
//
VSSQ_PUBLIC bool
vssq_messenger_has_creds(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_has_creds(self->auth);
}

//
//  Return user credentials.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_creds(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_creds(self->auth);
}

//
//  Check whether current credentials were backed up.
//
//  Prerequisites: credentials must be set.
//
VSSQ_PUBLIC bool
vssq_messenger_has_backup_creds(const vssq_messenger_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_has_backup_creds(self->auth, error);
}

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: credentials must be set.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_backup_creds(const vssq_messenger_t *self, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_backup_creds(self->auth, pwd);
}

//
//  Authenticate user by using backup cerdentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_authenticate_with_backup_creds(vssq_messenger_t *self, vsc_str_t username, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_restore_creds(self->auth, username, pwd);
}

//
//  Remove credentials beckup from the secure cloud storage (Keyknox).
//
//  Prerequisites: credentials must be set.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_remove_creds_backup(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_remove_creds_backup(self->auth);
}

//
//  Return authentication module.
//
//  It should be used with great carefulness and responsibility.
//
VSSQ_PUBLIC const vssq_messenger_auth_t *
vssq_messenger_auth(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);

    return self->auth;
}
