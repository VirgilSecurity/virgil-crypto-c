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
#include "vssq_messenger_defs.h"
#include "vssq_messenger_group_private.h"
#include "vssq_messenger_user_list_private.h"

#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_padding_params.h>
#include <virgil/crypto/foundation/vscf_random_padding.h>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/sdk/core/vssc_card_client.h>
#include <virgil/sdk/core/vssc_card_manager.h>
#include <virgil/crypto/foundation/vscf_status.h>

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
//  Initialize messenger with a custom configuration.
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
//  Map status from the "foundation" library to a status related to the message decryption.
//
static vssq_status_t
vssq_messenger_map_foundation_status_of_decryption(vscf_status_t foundation_status) VSSQ_NODISCARD;

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
//  Initialize messenger with a custom configuration.
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
//  Initialize messenger with a custom configuration.
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
    self->contacts = vssq_messenger_contacts_new();
    vssq_messenger_contacts_use_auth(self->contacts, self->auth);
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
    vssq_messenger_contacts_delete(self->contacts);
}

//
//  Initialize messenger with a custom configuration.
//
static void
vssq_messenger_init_ctx_with_config(vssq_messenger_t *self, const vssq_messenger_config_t *config) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(config);

    self->config = vssq_messenger_config_shallow_copy_const(config);
    self->auth = vssq_messenger_auth_new_with_config(self->config);
    self->contacts = vssq_messenger_contacts_new();
    vssq_messenger_contacts_use_auth(self->contacts, self->auth);
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

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        const vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return vssq_status_RNG_FAILED;
        }
        vssq_messenger_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vssq_status_SUCCESS;
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
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_is_authenticated(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_is_authenticated(self->auth);
}

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_user(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));

    return vssq_messenger_auth_user(self->auth);
}

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_user_modifiable(vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));

    return vssq_messenger_auth_user_modifiable(self->auth);
}

//
//  Return name of the current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vsc_str_t
vssq_messenger_username(const vssq_messenger_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));

    return vssq_messenger_user_username(vssq_messenger_auth_user(self->auth));
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
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_has_backup_creds(const vssq_messenger_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_has_backup_creds(self->auth, error);
}

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_backup_creds(const vssq_messenger_t *self, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_backup_creds(self->auth, pwd);
}

//
//  Authenticate user by using backup credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_authenticate_with_backup_creds(vssq_messenger_t *self, vsc_str_t username, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);

    return vssq_messenger_auth_restore_creds(self->auth, username, pwd);
}

//
//  Remove credentials backup from the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
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

//
//  Return founded user or error.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_find_user_with_identity(const vssq_messenger_t *self, vsc_str_t identity, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(identity));

    vssc_string_list_t *identities = vssc_string_list_new();
    vssc_string_list_add(identities, identity);

    vssq_messenger_user_list_t *founded_users = vssq_messenger_find_users_with_identities(self, identities, error);

    vssq_messenger_user_t *founded_user = NULL;

    if ((NULL != founded_users) && vssq_messenger_user_list_has_item(founded_users)) {
        founded_user = vssq_messenger_user_shallow_copy(vssq_messenger_user_list_item_modifiable(founded_users));
    }

    vssc_string_list_destroy(&identities);
    vssq_messenger_user_list_destroy(&founded_users);

    return founded_user;
}

//
//  Return founded users or error.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_with_identities(
        const vssq_messenger_t *self, const vssc_string_list_t *identities, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT_PTR(identities);
    VSSQ_ASSERT(vssc_string_list_has_item(identities));

    //
    // Declare vars.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_card_manager_t *card_manager = NULL;
    vssc_card_client_t *card_client = NULL;
    vssc_http_request_t *search_cards_request = NULL;
    vssc_http_response_t *search_cards_response = NULL;
    vssc_raw_card_list_t *founded_raw_cards = NULL;
    vssc_card_list_t *founded_cards = NULL;
    vssq_messenger_user_list_t *founded_users = NULL;

    //
    //  Configure algorithms.
    //
    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, self->random);

    core_sdk_error.status = vssc_card_manager_configure(card_manager);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_SEARCH_CARD_FAILED_INIT_FAILED);
        goto cleanup;
    }

    //
    //  Send request.
    //
    card_client = vssc_card_client_new();

    search_cards_request = vssc_card_client_make_request_search_cards_with_identities(card_client, identities);

    search_cards_response = vssq_messenger_auth_send_virgil_request(self->auth, search_cards_request, error);

    if (NULL == search_cards_response) {
        goto cleanup;
    }

    if (vssc_http_response_status_code(search_cards_response) == 404) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_NOT_FOUND);
        goto cleanup;
    }

    if (!vssc_http_response_is_success(search_cards_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_SEARCH_CARD_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    founded_raw_cards = vssc_card_client_process_response_search_cards(search_cards_response, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_SEARCH_CARD_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    //
    //  Import cards.
    //
    founded_cards = vssc_card_manager_import_raw_card_list(card_manager, founded_raw_cards, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_SEARCH_CARD_FAILED_IMPORT_FAILED);
        goto cleanup;
    }

    //
    //  Create Users from the Cards.
    //
    if (!vssc_card_list_has_item(founded_cards)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_NOT_FOUND);
        goto cleanup;
    }

    founded_users = vssq_messenger_user_list_new();

    for (const vssc_card_list_t *card_it = founded_cards; (card_it != NULL) && vssc_card_list_has_item(card_it);
            card_it = vssc_card_list_next(card_it)) {

        const vssc_card_t *user_card = vssc_card_list_item(card_it);
        vssq_messenger_user_t *user = vssq_messenger_user_new_with_card(user_card);
        vssq_messenger_user_list_add_disown(founded_users, &user);
    }

cleanup:
    vssc_card_manager_destroy(&card_manager);
    vssc_card_client_destroy(&card_client);
    vssc_http_request_destroy(&search_cards_request);
    vssc_http_response_destroy(&search_cards_response);
    vssc_raw_card_list_destroy(&founded_raw_cards);
    vssc_card_list_destroy(&founded_cards);

    return founded_users;
}

//
//  Return founded user or error.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_find_user_with_username(const vssq_messenger_t *self, vsc_str_t username, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));

    //
    //  Find identity for a given username via Contact Discovery.
    //
    vssc_string_list_t *usernames = vssc_string_list_new();
    vssc_string_list_add(usernames, username);

    vssc_string_map_t *usernames_to_identities =
            vssq_messenger_contacts_discover_usernames(self->contacts, usernames, error);

    vssc_string_list_destroy(&usernames);

    if (NULL == usernames_to_identities) {
        return NULL;
    }

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_t identity = vssc_string_map_get(usernames_to_identities, username, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_NOT_FOUND);
        vssc_string_map_destroy(&usernames_to_identities);
        return NULL;
    }

    //
    //  Get user with identity.
    //
    vssq_messenger_user_t *founded_user = vssq_messenger_find_user_with_identity(self, identity, error);
    if (founded_user) {
        vssq_messenger_user_set_username(founded_user, username);
    }

    vssc_string_map_destroy(&usernames_to_identities);

    return founded_user;
}

//
//  Return founded users.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_by_phones(
        const vssq_messenger_t *self, const vssc_string_list_t *phones, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT_PTR(phones);
    VSSQ_ASSERT(vssc_string_list_has_item(phones));

    //
    //  Find identity for a given phone numbers via Contact Discovery.
    //
    vssc_string_map_t *phone_numbers_to_identities =
            vssq_messenger_contacts_discover_phone_numbers(self->contacts, phones, error);

    if (NULL == phone_numbers_to_identities) {
        return NULL;
    }

    //
    //  Get user with identity.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_string_list_t *identities = vssc_string_map_values(phone_numbers_to_identities);

    vssq_messenger_user_list_t *founded_users = vssq_messenger_find_users_with_identities(self, identities, error);

    vssc_string_list_destroy(&identities);

    vssc_string_map_t *identities_to_phone_numbers = vssc_string_map_swap_key_values(phone_numbers_to_identities);

    for (vssq_messenger_user_list_t *user_it = founded_users;
            (user_it != NULL) && vssq_messenger_user_list_has_item(user_it);
            user_it = vssq_messenger_user_list_next_modifiable(user_it)) {


        vssq_messenger_user_t *user = vssq_messenger_user_list_item_modifiable(user_it);
        vsc_str_t user_identity = vssq_messenger_user_identity(user);

        vsc_str_t user_phone_number = vssc_string_map_get(identities_to_phone_numbers, user_identity, NULL);
        VSSQ_ASSERT_SAFE(vsc_str_is_valid_and_non_empty(user_phone_number));

        vssq_messenger_user_set_phone_number(user, user_phone_number);
    }

    vssc_string_map_destroy(&identities_to_phone_numbers);
    vssc_string_map_destroy(&phone_numbers_to_identities);

    return founded_users;
}

//
//  Return founded users.
//
VSSQ_PUBLIC vssq_messenger_user_list_t *
vssq_messenger_find_users_by_emails(
        const vssq_messenger_t *self, const vssc_string_list_t *emails, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT_PTR(emails);
    VSSQ_ASSERT(vssc_string_list_has_item(emails));

    //
    //  Find identity for a given email numbers via Contact Discovery.
    //
    vssc_string_map_t *emails_to_identities = vssq_messenger_contacts_discover_emails(self->contacts, emails, error);

    if (NULL == emails_to_identities) {
        return NULL;
    }

    //
    //  Get user with identity.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_string_list_t *identities = vssc_string_map_values(emails_to_identities);

    vssq_messenger_user_list_t *founded_users = vssq_messenger_find_users_with_identities(self, identities, error);

    vssc_string_list_destroy(&identities);

    vssc_string_map_t *identities_to_emails = vssc_string_map_swap_key_values(emails_to_identities);

    for (vssq_messenger_user_list_t *user_it = founded_users;
            (user_it != NULL) && vssq_messenger_user_list_has_item(user_it);
            user_it = vssq_messenger_user_list_next_modifiable(user_it)) {


        vssq_messenger_user_t *user = vssq_messenger_user_list_item_modifiable(user_it);
        vsc_str_t user_identity = vssq_messenger_user_identity(user);

        vsc_str_t user_email_number = vssc_string_map_get(identities_to_emails, user_identity, NULL);
        VSSQ_ASSERT_SAFE(vsc_str_is_valid_and_non_empty(user_email_number));

        vssq_messenger_user_set_email(user, user_email_number);
    }

    vssc_string_map_destroy(&identities_to_emails);
    vssc_string_map_destroy(&emails_to_identities);

    return founded_users;
}

//
//  Register user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_add_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(phone_number));

    return vssq_messenger_contacts_add_phone_number(self->contacts, phone_number);
}

//
//  Confirm user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_confirm_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number, vsc_str_t confirmation_code) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(phone_number));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(confirmation_code));

    return vssq_messenger_contacts_confirm_phone_number(self->contacts, phone_number, confirmation_code);
}

//
//  Delete user's phone number.
//
//  Prerequisites: phone numbers are formatted according to E.164 standard.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_delete_phone_number(const vssq_messenger_t *self, vsc_str_t phone_number) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(phone_number));

    return vssq_messenger_contacts_delete_phone_number(self->contacts, phone_number);
}

//
//  Register user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_add_email(const vssq_messenger_t *self, vsc_str_t email) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(email));

    return vssq_messenger_contacts_add_email(self->contacts, email);
}

//
//  Confirm user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_confirm_email(const vssq_messenger_t *self, vsc_str_t email, vsc_str_t confirmation_code) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(email));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(confirmation_code));

    return vssq_messenger_contacts_confirm_email(self->contacts, email, confirmation_code);
}

//
//  Delete user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_delete_email(const vssq_messenger_t *self, vsc_str_t email) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(email));

    return vssq_messenger_contacts_delete_email(self->contacts, email);
}

//
//  Return a buffer length enough to hold an encrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_encrypted_message_len(
        const vssq_messenger_t *self, size_t message_len, const vssq_messenger_user_t *recipient) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT_PTR(recipient);

    return 1024 + message_len + (vscf_padding_params_DEFAULT_FRAME - message_len % vscf_padding_params_DEFAULT_FRAME);
}

//
//  Encrypt a text message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_encrypt_text(
        const vssq_messenger_t *self, vsc_str_t text, const vssq_messenger_user_t *recipient, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid(text));
    VSSQ_ASSERT(vsc_buffer_is_valid(out));

    return vssq_messenger_encrypt_data(self, vsc_str_as_data(text), recipient, out);
}

//
//  Encrypt a binary message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_encrypt_data(
        const vssq_messenger_t *self, vsc_data_t data, const vssq_messenger_user_t *recipient, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT(vsc_data_is_valid(data));
    VSSQ_ASSERT_PTR(recipient);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_encrypted_message_len(self, data.len, recipient));

    //
    // Get Sender's info.
    //
    const vssq_messenger_user_t *sender = vssq_messenger_auth_user(self->auth);
    const vscf_impl_t *sender_private_key = vssq_messenger_auth_private_key(self->auth);
    const vscf_impl_t *sender_public_key = vssq_messenger_user_public_key(sender);
    vsc_data_t sender_public_key_id = vssq_messenger_user_public_key_id(sender);

    //
    // Get Recipient's info.
    //
    const vscf_impl_t *recipient_public_key = vssq_messenger_user_public_key(recipient);
    vsc_data_t recipient_public_key_id = vssq_messenger_user_public_key_id(recipient);

    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_recipient_cipher_t *cipher = NULL;

    vssq_status_t status = vssq_status_SUCCESS;

    //
    //  Encrypt message.
    //
    vscf_random_padding_t *random_padding = vscf_random_padding_new();
    vscf_random_padding_use_random(random_padding, self->random);

    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);
    vscf_recipient_cipher_take_encryption_padding(cipher, vscf_random_padding_impl(random_padding));
    random_padding = NULL;

    vscf_recipient_cipher_add_key_recipient(cipher, recipient_public_key_id, recipient_public_key);

    vscf_recipient_cipher_add_key_recipient(cipher, sender_public_key_id, sender_public_key);

    foundation_error.status = vscf_recipient_cipher_add_signer(cipher, sender_public_key_id, sender_private_key);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_start_signed_encryption(cipher, data.len);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    vscf_recipient_cipher_pack_message_info(cipher, out);

    foundation_error.status = vscf_recipient_cipher_process_encryption(cipher, data, out);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_finish_encryption(cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_pack_message_info_footer(cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
        goto cleanup;
    }

cleanup:
    vscf_recipient_cipher_destroy(&cipher);

    return status;
}

//
//  Return a buffer length enough to hold a decrypted message.
//
VSSQ_PUBLIC size_t
vssq_messenger_decrypted_message_len(const vssq_messenger_t *self, size_t encrypted_message_len) {
    VSSQ_ASSERT_PTR(self);

    vscf_recipient_cipher_t *cipher = vscf_recipient_cipher_new();

    const size_t decrypted_message_len = vscf_recipient_cipher_decryption_out_len(cipher, encrypted_message_len) +
                                         vscf_recipient_cipher_decryption_out_len(cipher, 0);

    vscf_recipient_cipher_destroy(&cipher);

    return decrypted_message_len;
}

//
//  Decrypt a text message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_decrypt_text(const vssq_messenger_t *self, vsc_data_t encrypted_text,
        const vssq_messenger_user_t *sender, vsc_str_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_data_is_valid(encrypted_text));
    VSSQ_ASSERT_PTR(sender);
    VSSQ_ASSERT(vsc_str_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_str_buffer_unused_len(out) >= vssq_messenger_decrypted_message_len(self, encrypted_text.len));

    return vssq_messenger_decrypt_data(self, encrypted_text, sender, &out->buffer);
}

//
//  Decrypt a binary message.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_decrypt_data(const vssq_messenger_t *self, vsc_data_t encrypted_data,
        const vssq_messenger_user_t *sender, vsc_buffer_t *out) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));
    VSSQ_ASSERT(vsc_data_is_valid(encrypted_data));
    VSSQ_ASSERT_PTR(sender);
    VSSQ_ASSERT(vsc_buffer_is_valid(out));
    VSSQ_ASSERT(vsc_buffer_unused_len(out) >= vssq_messenger_decrypted_message_len(self, encrypted_data.len));

    //
    // Get Recipient's info.
    //
    const vssq_messenger_user_t *recipient = vssq_messenger_auth_user(self->auth);
    const vscf_impl_t *recipient_private_key = vssq_messenger_auth_private_key(self->auth);
    vsc_data_t recipient_public_key_id = vssq_messenger_user_public_key_id(recipient);

    //
    // Get Sender's info.
    //
    const vscf_impl_t *sender_public_key = vssq_messenger_user_public_key(sender);
    vsc_data_t sender_public_key_id = vssq_messenger_user_public_key_id(sender);


    //
    //  Declare vars.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vscf_recipient_cipher_t *cipher = NULL;

    vssq_status_t status = vssq_status_SUCCESS;

    //
    //  Decrypt message.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    foundation_error.status = vscf_recipient_cipher_start_decryption_with_key(
            cipher, recipient_public_key_id, recipient_private_key, vsc_data_empty());

    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_messenger_map_foundation_status_of_decryption(vscf_error_status(&foundation_error));
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_process_decryption(cipher, encrypted_data, out);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_messenger_map_foundation_status_of_decryption(vscf_error_status(&foundation_error));
        goto cleanup;
    }

    foundation_error.status = vscf_recipient_cipher_finish_decryption(cipher, out);
    if (vscf_error_has_error(&foundation_error)) {
        status = vssq_messenger_map_foundation_status_of_decryption(vscf_error_status(&foundation_error));
        goto cleanup;
    }

    //
    //  Verify.
    //
    if (!vscf_recipient_cipher_is_data_signed(cipher)) {
        status = vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE;
        goto cleanup;
    }

    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(cipher);

    if (!vscf_signer_info_list_has_item(signer_infos)) {
        status = vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE;
        goto cleanup;
    }

    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);

    vsc_data_t signer_id = vscf_signer_info_signer_id(signer_info);
    if (!vsc_data_equal(signer_id, sender_public_key_id)) {
        status = vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE;
        goto cleanup;
    }

    const bool verified = vscf_recipient_cipher_verify_signer_info(cipher, signer_info, sender_public_key);

    if (!verified) {
        status = vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE;
        goto cleanup;
    }


cleanup:
    vscf_recipient_cipher_destroy(&cipher);

    return status;
}

//
//  Create a new group for a group messaging.
//
//  Prerequisites: user should be authenticated.
//  Note, group owner is added to the participants automatically.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_create_group(const vssq_messenger_t *self, vsc_str_t group_id,
        const vssq_messenger_user_list_t *participants, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(group_id));
    VSSQ_ASSERT_PTR(participants);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));

    vssq_messenger_group_t *group = vssq_messenger_group_new();
    vssq_messenger_group_use_random(group, self->random);
    vssq_messenger_group_use_auth(group, self->auth);

    const vssq_status_t status = vssq_messenger_group_create(group, group_id, participants);
    if (status != vssq_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        vssq_messenger_group_destroy(&group);
        return NULL;
    }

    return group;
}

//
//  Load an existing group for a group messaging.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_group_t *
vssq_messenger_load_group(
        const vssq_messenger_t *self, vsc_str_t group_id, const vssq_messenger_user_t *owner, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(group_id));
    VSSQ_ASSERT_PTR(owner);
    VSSQ_ASSERT(vssq_messenger_is_authenticated(self));

    vssq_messenger_group_t *group = vssq_messenger_group_new();
    vssq_messenger_group_use_random(group, self->random);
    vssq_messenger_group_use_auth(group, self->auth);

    const vssq_status_t status = vssq_messenger_group_load(group, group_id, owner);
    if (status != vssq_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        vssq_messenger_group_destroy(&group);
        return NULL;
    }

    return group;
}

//
//  Map status from the "foundation" library to a status related to the message decryption.
//
static vssq_status_t
vssq_messenger_map_foundation_status_of_decryption(vscf_status_t foundation_status) {

    switch (foundation_status) {
    case vscf_status_SUCCESS:
        return vssq_status_SUCCESS;

    case vscf_status_ERROR_NO_MESSAGE_INFO:
    case vscf_status_ERROR_BAD_MESSAGE_INFO:
    case vscf_status_ERROR_AUTH_FAILED:
        return vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_INVALID_ENCRYPTED_MESSAGE;

    case vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
        return vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_RECIPIENT_NOT_FOUND;

    case vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
        return vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_WRONG_PRIVATE_KEY;

    default:
        return vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED;
    }
}
