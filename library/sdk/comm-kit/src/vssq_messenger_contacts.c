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
//  Provides access to the messenger contacts endpoints.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_contacts.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_contacts_defs.h"
#include "vssq_messenger_creds_private.h"
#include "vssq_messenger_user_private.h"
#include "vssq_contact_utils.h"

#include <stdio.h>
#include <virgil/crypto/common/vsc_data.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_str_mutable.h>
#include <virgil/crypto/common/private/vsc_str_buffer_defs.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_key_material_rng.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_recipient_cipher.h>
#include <virgil/crypto/foundation/vscf_signer.h>
#include <virgil/crypto/foundation/vscf_base64.h>
#include <virgil/crypto/foundation/private/vscf_base64_private.h>
#include <virgil/crypto/foundation/vscf_binary.h>
#include <virgil/crypto/pythia/vscp_pythia.h>
#include <virgil/sdk/core/vssc_unix_time.h>
#include <virgil/sdk/core/vssc_virgil_http_client.h>
#include <virgil/sdk/core/vssc_card_client.h>
#include <virgil/sdk/core/vssc_card_manager.h>
#include <virgil/sdk/core/vssc_raw_card.h>
#include <virgil/sdk/core/vssc_json_object.h>
#include <virgil/sdk/core/private/vssc_json_object_private.h>
#include <virgil/sdk/keyknox/vssk_keyknox_client.h>
#include <virgil/sdk/pythia/vssp_pythia_client.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_contacts_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_contacts_init_ctx(vssq_messenger_contacts_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_contacts_cleanup_ctx(vssq_messenger_contacts_t *self);

//
//  Generic discovery.
//  Return map contact->identity.
//
static vssc_string_map_t *
vssq_messenger_contacts_generic_discover(const vssq_messenger_contacts_t *self,
        const vssc_string_map_t *contacts_to_hashes, vsc_str_t contacts_discovery_url_path,
        vsc_str_t contacts_hashes_json_key, vsc_str_t contacts_hashes_to_identities_json_key, vssq_error_t *error);

static const char k_url_path_username_discovery_chars[] = "/username-discovery";

static const vsc_str_t k_url_path_username_discovery = {
    k_url_path_username_discovery_chars,
    sizeof(k_url_path_username_discovery_chars) - 1
};

static const char k_url_path_phone_add_chars[] = "/phone-add";

static const vsc_str_t k_url_path_phone_add = {
    k_url_path_phone_add_chars,
    sizeof(k_url_path_phone_add_chars) - 1
};

static const char k_url_path_phone_confirm_chars[] = "/phone-confirm";

static const vsc_str_t k_url_path_phone_confirm = {
    k_url_path_phone_confirm_chars,
    sizeof(k_url_path_phone_confirm_chars) - 1
};

static const char k_url_path_phone_delete_chars[] = "/phone-delete";

static const vsc_str_t k_url_path_phone_delete = {
    k_url_path_phone_delete_chars,
    sizeof(k_url_path_phone_delete_chars) - 1
};

static const char k_url_path_phone_discovery_chars[] = "/phone-discovery";

static const vsc_str_t k_url_path_phone_discovery = {
    k_url_path_phone_discovery_chars,
    sizeof(k_url_path_phone_discovery_chars) - 1
};

static const char k_url_path_email_add_chars[] = "/email-add";

static const vsc_str_t k_url_path_email_add = {
    k_url_path_email_add_chars,
    sizeof(k_url_path_email_add_chars) - 1
};

static const char k_url_path_email_confirm_chars[] = "/email-confirm";

static const vsc_str_t k_url_path_email_confirm = {
    k_url_path_email_confirm_chars,
    sizeof(k_url_path_email_confirm_chars) - 1
};

static const char k_url_path_email_delete_chars[] = "/email-delete";

static const vsc_str_t k_url_path_email_delete = {
    k_url_path_email_delete_chars,
    sizeof(k_url_path_email_delete_chars) - 1
};

static const char k_url_path_email_discovery_chars[] = "/email-discovery";

static const vsc_str_t k_url_path_email_discovery = {
    k_url_path_email_discovery_chars,
    sizeof(k_url_path_email_discovery_chars) - 1
};

static const char k_json_key_phone_number_chars[] = "phone_number";

static const vsc_str_t k_json_key_phone_number = {
    k_json_key_phone_number_chars,
    sizeof(k_json_key_phone_number_chars) - 1
};

static const char k_json_key_phone_hashes_chars[] = "phone_hashes";

static const vsc_str_t k_json_key_phone_hashes = {
    k_json_key_phone_hashes_chars,
    sizeof(k_json_key_phone_hashes_chars) - 1
};

static const char k_json_key_phone_numbers_to_identities_chars[] = "phone_numbers_to_identities";

static const vsc_str_t k_json_key_phone_numbers_to_identities = {
    k_json_key_phone_numbers_to_identities_chars,
    sizeof(k_json_key_phone_numbers_to_identities_chars) - 1
};

static const char k_json_key_email_chars[] = "email";

static const vsc_str_t k_json_key_email = {
    k_json_key_email_chars,
    sizeof(k_json_key_email_chars) - 1
};

static const char k_json_key_email_hashes_chars[] = "email_hashes";

static const vsc_str_t k_json_key_email_hashes = {
    k_json_key_email_hashes_chars,
    sizeof(k_json_key_email_hashes_chars) - 1
};

static const char k_json_key_emails_to_identities_chars[] = "emails_to_identities";

static const vsc_str_t k_json_key_emails_to_identities = {
    k_json_key_emails_to_identities_chars,
    sizeof(k_json_key_emails_to_identities_chars) - 1
};

static const char k_json_key_username_hashes_chars[] = "username_hashes";

static const vsc_str_t k_json_key_username_hashes = {
    k_json_key_username_hashes_chars,
    sizeof(k_json_key_username_hashes_chars) - 1
};

static const char k_json_key_username_hashes_to_identities_chars[] = "username_hashes_to_identities";

static const vsc_str_t k_json_key_username_hashes_to_identities = {
    k_json_key_username_hashes_to_identities_chars,
    sizeof(k_json_key_username_hashes_to_identities_chars) - 1
};

static const char k_json_key_confirmation_code_chars[] = "confirmation_code";

static const vsc_str_t k_json_key_confirmation_code = {
    k_json_key_confirmation_code_chars,
    sizeof(k_json_key_confirmation_code_chars) - 1
};

//
//  Return size of 'vssq_messenger_contacts_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_contacts_ctx_size(void) {

    return sizeof(vssq_messenger_contacts_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_init(vssq_messenger_contacts_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_contacts_t));

    self->refcnt = 1;

    vssq_messenger_contacts_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_cleanup(vssq_messenger_contacts_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_contacts_release_auth(self);

    vssq_messenger_contacts_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_contacts_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_contacts_t *
vssq_messenger_contacts_new(void) {

    vssq_messenger_contacts_t *self = (vssq_messenger_contacts_t *) vssq_alloc(sizeof (vssq_messenger_contacts_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_contacts_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_delete(const vssq_messenger_contacts_t *self) {

    vssq_messenger_contacts_t *local_self = (vssq_messenger_contacts_t *)self;

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

    vssq_messenger_contacts_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_contacts_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_destroy(vssq_messenger_contacts_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_contacts_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_contacts_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_contacts_t *
vssq_messenger_contacts_shallow_copy(vssq_messenger_contacts_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_contacts_t *
vssq_messenger_contacts_shallow_copy_const(const vssq_messenger_contacts_t *self) {

    return vssq_messenger_contacts_shallow_copy((vssq_messenger_contacts_t *)self);
}

//
//  Setup dependency to the class 'messenger auth' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_use_auth(vssq_messenger_contacts_t *self, vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = vssq_messenger_auth_shallow_copy(auth);
}

//
//  Setup dependency to the class 'messenger auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_take_auth(vssq_messenger_contacts_t *self, vssq_messenger_auth_t *auth) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(auth);
    VSSQ_ASSERT(self->auth == NULL);

    self->auth = auth;
}

//
//  Release dependency to the class 'messenger auth'.
//
VSSQ_PUBLIC void
vssq_messenger_contacts_release_auth(vssq_messenger_contacts_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_auth_destroy(&self->auth);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_contacts_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_contacts_init_ctx(vssq_messenger_contacts_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_contacts_cleanup_ctx(vssq_messenger_contacts_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Discover given user names.
//  Return map username->identity.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_usernames(
        const vssq_messenger_contacts_t *self, const vssc_string_list_t *usernames, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vssq_messenger_auth_is_authenticated(self->auth));
    VSSQ_ASSERT_PTR(usernames);
    VSSQ_ASSERT(vssc_string_list_has_item(usernames));

    vssq_error_t internal_error;
    vssq_error_reset(&internal_error);

    vssc_string_map_t *usernames_to_hashes = vssq_contact_utils_hash_usernames(usernames, &internal_error);
    if (vssq_error_has_error(&internal_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_error_status(&internal_error));
        return NULL;
    }

    vssc_string_map_t *result =
            vssq_messenger_contacts_generic_discover(self, usernames_to_hashes, k_url_path_username_discovery,
                    k_json_key_username_hashes, k_json_key_username_hashes_to_identities, &internal_error);

    VSSQ_ERROR_SAFE_UPDATE(error, vssq_error_status(&internal_error));

    vssc_string_map_destroy(&usernames_to_hashes);

    return result;
}

//
//  Register user's phone number.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_add_phone_number(
        const vssq_messenger_contacts_t *self, vsc_str_t phone_number, vsc_str_t country_code) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(phone_number);
    VSSQ_UNUSED(country_code);

    //  TODO: This is STUB. Implement me.


    VSSQ_UNUSED(k_url_path_username_discovery);
    VSSQ_UNUSED(k_url_path_phone_add);
    VSSQ_UNUSED(k_url_path_phone_confirm);
    VSSQ_UNUSED(k_url_path_phone_delete);
    VSSQ_UNUSED(k_url_path_phone_discovery);
    VSSQ_UNUSED(k_url_path_email_add);
    VSSQ_UNUSED(k_url_path_email_confirm);
    VSSQ_UNUSED(k_url_path_email_delete);
    VSSQ_UNUSED(k_url_path_email_discovery);
    VSSQ_UNUSED(k_json_key_phone_number);
    VSSQ_UNUSED(k_json_key_phone_hashes);
    VSSQ_UNUSED(k_json_key_phone_numbers_to_identities);
    VSSQ_UNUSED(k_json_key_email);
    VSSQ_UNUSED(k_json_key_email_hashes);
    VSSQ_UNUSED(k_json_key_emails_to_identities);
    VSSQ_UNUSED(k_json_key_username_hashes);
    VSSQ_UNUSED(k_json_key_username_hashes_to_identities);
    VSSQ_UNUSED(k_json_key_confirmation_code);


    return vssq_status_SUCCESS;
}

//
//  Confirm user's phone number.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_confirm_phone_number(const vssq_messenger_contacts_t *self, vsc_str_t phone_number,
        vsc_str_t country_code, vsc_str_t confirmation_code) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(phone_number);
    VSSQ_UNUSED(country_code);
    VSSQ_UNUSED(confirmation_code);

    //  TODO: This is STUB. Implement me.

    return vssq_status_SUCCESS;
}

//
//  Delete user's phone number.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_delete_phone_number(
        const vssq_messenger_contacts_t *self, vsc_str_t phone_number, vsc_str_t country_code) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(phone_number);
    VSSQ_UNUSED(country_code);

    //  TODO: This is STUB. Implement me.

    return vssq_status_SUCCESS;
}

//
//  Discover given phone numbers.
//  Return map phone->identity.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_phone_numbers(const vssq_messenger_contacts_t *self,
        const vssc_string_list_t *phone_numbers, vsc_str_t country_code, vssq_error_t *error) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(phone_numbers);
    VSSQ_UNUSED(country_code);
    VSSQ_UNUSED(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Register user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_add_email(const vssq_messenger_contacts_t *self, vsc_str_t email) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(email);

    //  TODO: This is STUB. Implement me.

    return vssq_status_SUCCESS;
}

//
//  Confirm user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_confirm_email(
        const vssq_messenger_contacts_t *self, vsc_str_t email, vsc_str_t confirmation_code) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(email);
    VSSQ_UNUSED(confirmation_code);

    //  TODO: This is STUB. Implement me.

    return vssq_status_SUCCESS;
}

//
//  Delete user's email.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_contacts_delete_email(const vssq_messenger_contacts_t *self, vsc_str_t email) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(email);

    //  TODO: This is STUB. Implement me.

    return vssq_status_SUCCESS;
}

//
//  Discover given emails.
//  Return map email->identity.
//
VSSQ_PUBLIC vssc_string_map_t *
vssq_messenger_contacts_discover_emails(
        const vssq_messenger_contacts_t *self, const vssc_string_list_t *emails, vssq_error_t *error) {

    VSSQ_UNUSED(self);
    VSSQ_UNUSED(emails);
    VSSQ_UNUSED(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Generic discovery.
//  Return map contact->identity.
//
static vssc_string_map_t *
vssq_messenger_contacts_generic_discover(const vssq_messenger_contacts_t *self,
        const vssc_string_map_t *contacts_to_hashes, vsc_str_t contacts_discovery_url_path,
        vsc_str_t contacts_hashes_json_key, vsc_str_t contacts_hashes_to_identities_json_key, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->auth);
    VSSQ_ASSERT(vssq_messenger_auth_is_authenticated(self->auth));
    VSSQ_ASSERT_PTR(contacts_to_hashes);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(contacts_discovery_url_path));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(contacts_hashes_json_key));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(contacts_hashes_to_identities_json_key));
    VSSQ_ASSERT_PTR(error);

    const vssq_messenger_config_t *config = vssq_messenger_auth_config(self->auth);

    //
    //  Declare vars.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vsc_str_mutable_t request_url = {NULL, 0};
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssc_json_array_t *contact_hashes_json = NULL;
    vssc_json_object_t *hashes_to_identities_json = NULL;
    vssc_json_object_t *http_request_json = NULL;
    vssc_string_list_t *contacts_hashes = NULL;
    vssc_string_map_t *hashes_to_identities = NULL;

    vssc_string_map_t *result = NULL;

    //
    //  Hash contacts.
    //
    contacts_hashes = vssc_string_map_values(contacts_to_hashes);

    //
    //  Make request.
    //
    contact_hashes_json = vssc_json_array_new();
    vssc_json_array_add_string_values(contact_hashes_json, contacts_hashes);

    http_request_json = vssc_json_object_new();
    vssc_json_object_add_array_value(http_request_json, contacts_hashes_json_key, contact_hashes_json);

    request_url =
            vsc_str_mutable_concat(vssq_messenger_config_contact_discovery_url(config), contacts_discovery_url_path);
    http_request = vssc_http_request_new_with_body(vssc_http_request_method_post, vsc_str_mutable_as_str(request_url),
            vssc_json_object_as_str(http_request_json));

    vsc_str_mutable_release(&request_url);

    //
    //  Send request.
    //
    http_response = vssq_messenger_auth_send_contact_discovery_request(self->auth, http_request, error);

    if (vssq_error_has_error(error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(error, vssq_status_CONTACTS_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    //
    //  Process response.
    //
    if (!vssc_http_response_body_is_json_object(http_response)) {
        vssq_error_update(error, vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    const vssc_json_object_t *http_body_json = vssc_http_response_body_as_json_object(http_response);

    hashes_to_identities_json =
            vssc_json_object_get_object_value(http_body_json, contacts_hashes_to_identities_json_key, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(error, vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    hashes_to_identities = vssc_json_object_as_string_map(hashes_to_identities_json, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(error, vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    result = vssq_contact_utils_merge_contact_discovery_maps(contacts_to_hashes, hashes_to_identities);

cleanup:
    vsc_str_mutable_release(&request_url);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssc_json_array_destroy(&contact_hashes_json);
    vssc_json_object_destroy(&hashes_to_identities_json);
    vssc_json_object_destroy(&http_request_json);
    vssc_string_list_destroy(&contacts_hashes);
    vssc_string_map_destroy(&hashes_to_identities);

    return result;
}
