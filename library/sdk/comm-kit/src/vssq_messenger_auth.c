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
//  Provides access to the messenger authentication endpoints.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_auth.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_auth_defs.h"
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
#include <virgil/crypto/common/vsc_str_buffer.h>
#include <virgil/sdk/core/vssc_card.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vssq_messenger_auth_CARD_IDENTITY_LEN = 16,
    vssq_messenger_auth_CARD_IDENTITY_LEN_HEX = 32,
    vssq_messenger_auth_VIRGIL_JWT_LEN_MAX = 512,
    vssq_messenger_auth_CONTACT_DISCOVERY_JWT_LEN_MAX = 512,
    vssq_messenger_auth_EJABBERD_JWT_LEN_MAX = 256,
    vssq_messenger_auth_AUTH_HEADER_LEN_MAX = 256,
    vssq_messenger_auth_USERNAME_DIGEST_LEN = 64
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_auth_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_auth_init_ctx(vssq_messenger_auth_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_auth_cleanup_ctx(vssq_messenger_auth_t *self);

//
//  Initialize with a custom configuration.
//
static void
vssq_messenger_auth_init_ctx_with_config(vssq_messenger_auth_t *self, const vssq_messenger_config_t *config);

//
//  Reset credentials and invalidate cache if credentials are new.
//
static void
vssq_messenger_auth_reset_creds(vssq_messenger_auth_t *self, const vssq_messenger_creds_t *creds);

//
//  Get JWT to use with Virgil Services based on the password.
//
//  Note, cache is not used.
//
static vssq_status_t
vssq_messenger_auth_refresh_virgil_jwt_with_password(const vssq_messenger_auth_t *self, vsc_str_t username,
        vsc_data_t pwd) VSSQ_NODISCARD;

//
//  Request Virgil JWt, Ejabberd JWT, or Virgil Contact Discovery JWT depends on the given endpoint.
//
static vssq_status_t
vssq_messenger_auth_request_token(const vssq_messenger_auth_t *self, vsc_str_t endpoint,
        vsc_str_buffer_t *jwt_str) VSSQ_NODISCARD;

//
//  Refresh Virgil Contact Discovery JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_virgil_jwt(const vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Refresh Virgil JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_contact_discovery_jwt(const vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Refresh Ejabberd JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_ejabberd_token(const vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Set a new password to the messenger backend to get Virgil JWT when try to restore the key.
//
//  Note, password must be 32 bytes.
//
static vssq_status_t
vssq_messenger_auth_reset_sign_in_password(const vssq_messenger_auth_t *self, vsc_data_t pwd) VSSQ_NODISCARD;

//
//  Use Pythia Service to generate private key that can decrypt the restored key.
//
//  Note, password must be 32 bytes.
//
static vscf_impl_t *
vssq_messenger_auth_generate_brain_key(const vssq_messenger_auth_t *self, vsc_data_t pwd, vssq_error_t *error);

//
//  Encrypt credentials and put it to the Keyknox entries.
//
static vssq_status_t
vssq_messenger_auth_keyknox_pack_creds(const vssq_messenger_auth_t *self, const vscf_impl_t *brain_private_key,
        vsc_buffer_t *keyknox_meta, vsc_buffer_t *keyknox_value) VSSQ_NODISCARD;

//
//  Decrypt Keyknox entries and get credentials from it.
//
static vssq_messenger_creds_t *
vssq_messenger_auth_keyknox_unpack_creds(const vssq_messenger_auth_t *self, vsc_str_t username,
        const vscf_impl_t *brain_private_key, vsc_data_t keyknox_meta, vsc_data_t keyknox_value, vssq_error_t *error);

//
//  Push Keyknox entries with credentials to the service.
//
static vssq_status_t
vssq_messenger_auth_keyknox_push_creds(const vssq_messenger_auth_t *self, vsc_data_t keyknox_meta,
        vsc_data_t keyknox_value) VSSQ_NODISCARD;

//
//  Pull Keyknox entries with credentials from the service.
//
static vssq_status_t
vssq_messenger_auth_keyknox_pull_creds(const vssq_messenger_auth_t *self, vsc_buffer_t *keyknox_meta,
        vsc_buffer_t *keyknox_value) VSSQ_NODISCARD;

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_virgil_jwt(const vssq_messenger_auth_t *self, vssc_jwt_t **virgil_jwt_ref);

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_contact_discovery_jwt(const vssq_messenger_auth_t *self,
        vssc_jwt_t **contact_discovery_jwt_ref);

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_ejabberd_jwt(const vssq_messenger_auth_t *self, vssq_ejabberd_jwt_t **ejabberd_jwt_ref);

//
//  Fetch and store self card or error.
//
//  Prerequisites: user should be authenticated.
//  Prerequisites: Virgil JWT should be set and not expired.
//
static vssq_status_t
vssq_messenger_auth_fetch_self_card(vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Create a new user based on the given card and credentials.
//
//  Prerequisites: user should be authenticated.
//
static void
vssq_messenger_auth_update_user(vssq_messenger_auth_t *self, vssc_card_t **card_ref);

static const char k_url_path_virgil_jwt_chars[] = "/virgil-jwt";

static const vsc_str_t k_url_path_virgil_jwt = {
    k_url_path_virgil_jwt_chars,
    sizeof(k_url_path_virgil_jwt_chars) - 1
};

static const char k_url_path_contact_discovery_jwt_chars[] = "/contact-discovery-jwt";

static const vsc_str_t k_url_path_contact_discovery_jwt = {
    k_url_path_contact_discovery_jwt_chars,
    sizeof(k_url_path_contact_discovery_jwt_chars) - 1
};

static const char k_url_path_ejabberd_jwt_chars[] = "/ejabberd-jwt";

static const vsc_str_t k_url_path_ejabberd_jwt = {
    k_url_path_ejabberd_jwt_chars,
    sizeof(k_url_path_ejabberd_jwt_chars) - 1
};

static const char k_url_path_signup_chars[] = "/signup";

static const vsc_str_t k_url_path_signup = {
    k_url_path_signup_chars,
    sizeof(k_url_path_signup_chars) - 1
};

static const char k_url_path_set_password_chars[] = "/set-password";

static const vsc_str_t k_url_path_set_password = {
    k_url_path_set_password_chars,
    sizeof(k_url_path_set_password_chars) - 1
};

static const char k_url_path_pwd_virgil_jwt_chars[] = "/pwd-virgil-jwt";

static const vsc_str_t k_url_path_pwd_virgil_jwt = {
    k_url_path_pwd_virgil_jwt_chars,
    sizeof(k_url_path_pwd_virgil_jwt_chars) - 1
};

static const char k_http_header_auth_type_virgil_chars[] = "Virgil";

static const vsc_str_t k_http_header_auth_type_virgil = {
    k_http_header_auth_type_virgil_chars,
    sizeof(k_http_header_auth_type_virgil_chars) - 1
};

static const char k_http_header_auth_type_virgil_msg_pwd_chars[] = "VirgilMsgPwd";

static const vsc_str_t k_http_header_auth_type_virgil_msg_pwd = {
    k_http_header_auth_type_virgil_msg_pwd_chars,
    sizeof(k_http_header_auth_type_virgil_msg_pwd_chars) - 1
};

static const char k_http_header_auth_type_virgil_contact_discovery_chars[] = "VirgilContDisc";

static const vsc_str_t k_http_header_auth_type_virgil_contact_discovery = {
    k_http_header_auth_type_virgil_contact_discovery_chars,
    sizeof(k_http_header_auth_type_virgil_contact_discovery_chars) - 1
};

static const char k_http_header_auth_type_bearer_chars[] = "Bearer";

static const vsc_str_t k_http_header_auth_type_bearer = {
    k_http_header_auth_type_bearer_chars,
    sizeof(k_http_header_auth_type_bearer_chars) - 1
};

static const char k_json_key_token_chars[] = "token";

static const vsc_str_t k_json_key_token = {
    k_json_key_token_chars,
    sizeof(k_json_key_token_chars) - 1
};

static const char k_json_key_raw_card_chars[] = "raw_card";

static const vsc_str_t k_json_key_raw_card = {
    k_json_key_raw_card_chars,
    sizeof(k_json_key_raw_card_chars) - 1
};

static const char k_json_key_virgil_card_chars[] = "virgil_card";

static const vsc_str_t k_json_key_virgil_card = {
    k_json_key_virgil_card_chars,
    sizeof(k_json_key_virgil_card_chars) - 1
};

static const char k_json_key_password_chars[] = "password";

static const vsc_str_t k_json_key_password = {
    k_json_key_password_chars,
    sizeof(k_json_key_password_chars) - 1
};

static const char k_json_key_username_chars[] = "username";

static const vsc_str_t k_json_key_username = {
    k_json_key_username_chars,
    sizeof(k_json_key_username_chars) - 1
};

static const char k_brain_key_json_version_chars[] = "version";

static const vsc_str_t k_brain_key_json_version = {
    k_brain_key_json_version_chars,
    sizeof(k_brain_key_json_version_chars) - 1
};

static const char k_brain_key_json_card_id_chars[] = "card_id";

static const vsc_str_t k_brain_key_json_card_id = {
    k_brain_key_json_card_id_chars,
    sizeof(k_brain_key_json_card_id_chars) - 1
};

static const char k_brain_key_json_private_key_chars[] = "private_key";

static const vsc_str_t k_brain_key_json_private_key = {
    k_brain_key_json_private_key_chars,
    sizeof(k_brain_key_json_private_key_chars) - 1
};

static const char k_brain_v1_chars[] = "v1";

static const vsc_str_t k_brain_v1 = {
    k_brain_v1_chars,
    sizeof(k_brain_v1_chars) - 1
};

static const char k_brain_key_recipient_id_chars[] = "brain_key";

static const vsc_str_t k_brain_key_recipient_id = {
    k_brain_key_recipient_id_chars,
    sizeof(k_brain_key_recipient_id_chars) - 1
};

static const char k_keyknox_root_messenger_chars[] = "messenger";

static const vsc_str_t k_keyknox_root_messenger = {
    k_keyknox_root_messenger_chars,
    sizeof(k_keyknox_root_messenger_chars) - 1
};

static const char k_keyknox_path_credentials_chars[] = "credentials";

static const vsc_str_t k_keyknox_path_credentials = {
    k_keyknox_path_credentials_chars,
    sizeof(k_keyknox_path_credentials_chars) - 1
};

static const char k_keyknox_alias_sign_in_chars[] = "sign_in";

static const vsc_str_t k_keyknox_alias_sign_in = {
    k_keyknox_alias_sign_in_chars,
    sizeof(k_keyknox_alias_sign_in_chars) - 1
};

//
//  Return size of 'vssq_messenger_auth_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_auth_ctx_size(void) {

    return sizeof(vssq_messenger_auth_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init(vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_auth_t));

    self->refcnt = 1;

    vssq_messenger_auth_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_auth_cleanup(vssq_messenger_auth_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_auth_release_random(self);

    vssq_messenger_auth_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_auth_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new(void) {

    vssq_messenger_auth_t *self = (vssq_messenger_auth_t *) vssq_alloc(sizeof (vssq_messenger_auth_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_auth_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Initialize with a custom configuration.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init_with_config(vssq_messenger_auth_t *self, const vssq_messenger_config_t *config) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_auth_t));

    self->refcnt = 1;

    vssq_messenger_auth_init_ctx_with_config(self, config);
}

//
//  Allocate class context and perform it's initialization.
//  Initialize with a custom configuration.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new_with_config(const vssq_messenger_config_t *config) {

    vssq_messenger_auth_t *self = (vssq_messenger_auth_t *) vssq_alloc(sizeof (vssq_messenger_auth_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_auth_init_with_config(self, config);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_auth_delete(const vssq_messenger_auth_t *self) {

    vssq_messenger_auth_t *local_self = (vssq_messenger_auth_t *)self;

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

    vssq_messenger_auth_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_auth_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_destroy(vssq_messenger_auth_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_auth_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_auth_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy(vssq_messenger_auth_t *self) {

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
VSSQ_PUBLIC const vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy_const(const vssq_messenger_auth_t *self) {

    return vssq_messenger_auth_shallow_copy((vssq_messenger_auth_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_auth_use_random(vssq_messenger_auth_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_auth_take_random(vssq_messenger_auth_t *self, vscf_impl_t *random) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(random);
    VSSQ_ASSERT(self->random == NULL);

    VSSQ_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_release_random(vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_auth_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_auth_init_ctx(vssq_messenger_auth_t *self) {

    VSSQ_UNUSED(self);
    VSSQ_ASSERT(0 && "The default constructor is forbidden.");
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_auth_cleanup_ctx(vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_config_delete(self->config);
    vssq_messenger_creds_delete(self->creds);
    vssq_messenger_user_destroy(&self->user);
    vssc_jwt_destroy(&self->virgil_jwt);
    vssc_jwt_destroy(&self->contact_discovery_jwt);
    vssq_ejabberd_jwt_destroy(&self->ejabberd_jwt);

    vscp_pythia_cleanup();
}

//
//  Initialize with a custom configuration.
//
static void
vssq_messenger_auth_init_ctx_with_config(vssq_messenger_auth_t *self, const vssq_messenger_config_t *config) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(config);

    self->config = vssq_messenger_config_shallow_copy_const(config);

    const vscp_status_t pythia_config_status = vscp_pythia_configure();
    VSSQ_ASSERT_PROJECT_PYTHIA_SUCCESS(pythia_config_status);
}

//
//  Return configuration.
//
VSSQ_PUBLIC const vssq_messenger_config_t *
vssq_messenger_auth_config(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->config);

    return self->config;
}

//
//  Register a new user with a given name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_register(vssq_messenger_auth_t *self, vsc_str_t username) {

    //
    //  Check prerequisites.
    //
    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->config);
    VSSQ_ASSERT_PTR(vsc_str_is_valid_and_non_empty(username));

    //
    //  Prepare vars and algorithms.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    vsc_str_mutable_t request_url = {NULL, 0};

    vscf_impl_t *card_private_key = NULL;
    vsc_buffer_t *card_identity_bytes = NULL;
    vsc_str_buffer_t *card_identity = NULL;

    vssc_card_manager_t *card_manager = NULL;
    vssc_raw_card_t *initial_raw_card = NULL;
    vssc_raw_card_t *registered_raw_card = NULL;
    vssc_card_t *registered_card = NULL;

    vssc_json_object_t *initial_raw_card_json = NULL;
    vssc_json_object_t *register_raw_card_json = NULL;
    vssc_json_object_t *registered_raw_card_json = NULL;

    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssc_http_response_t *register_card_response = NULL;

    vssq_messenger_creds_t *new_creds = NULL;

    //
    //  Generate identity for a new Card.
    //
    card_identity_bytes = vsc_buffer_new_with_capacity(vssq_messenger_auth_CARD_IDENTITY_LEN);
    foundation_error.status = vscf_random(self->random, vssq_messenger_auth_CARD_IDENTITY_LEN, card_identity_bytes);
    if (vscf_error_has_error(&foundation_error)) {
        vssq_error_update(&error, vssq_status_GENERATE_IDENTITY_FAILED);
        goto cleanup;
    }

    card_identity = vsc_str_buffer_new_with_capacity(vssq_messenger_auth_CARD_IDENTITY_LEN_HEX);
    vscf_binary_to_hex(vsc_buffer_data(card_identity_bytes), card_identity);

    vsc_buffer_destroy(&card_identity_bytes);

    //
    //  Generate Key Pair for a new Card.
    //
    card_private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &foundation_error);
    if (vscf_error_has_error(&foundation_error)) {
        vssq_error_update(&error, vssq_status_GENERATE_PRIVATE_KEY_FAILED);
        goto cleanup;
    }

    //
    //  Generate a new Raw Card.
    //
    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, self->random);
    core_sdk_error.status = vssc_card_manager_configure(card_manager);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_CREATE_CARD_MANAGER_FAILED);
        goto cleanup;
    }

    initial_raw_card = vssc_card_manager_generate_raw_card(
            card_manager, vsc_str_buffer_str(card_identity), card_private_key, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_GENERATE_CARD_FAILED);
        goto cleanup;
    }

    //
    //  Register a new Raw Card.
    //
    initial_raw_card_json = vssc_raw_card_export_as_json(initial_raw_card);

    register_raw_card_json = vssc_json_object_new();
    vssc_json_object_add_object_value(register_raw_card_json, k_json_key_raw_card, initial_raw_card_json);

    vssc_json_object_add_string_value(register_raw_card_json, k_json_key_username, username);

    request_url = vsc_str_mutable_concat(vssq_messenger_config_messenger_url(self->config), k_url_path_signup);

    http_request = vssc_http_request_new_with_body(vssc_http_request_method_post, vsc_str_mutable_as_str(request_url),
            vssc_json_object_as_str(register_raw_card_json));

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);

    http_response = vssq_messenger_auth_send_messenger_request(self, http_request, false, &error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_REGISTER_CARD_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    if (!vssc_http_response_body_is_json_object(http_response)) {
        vssq_error_update(&error, vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    registered_raw_card_json = vssc_json_object_get_object_value(
            vssc_http_response_body_as_json_object(http_response), k_json_key_virgil_card, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    registered_raw_card = vssc_raw_card_import_from_json(registered_raw_card_json, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    //
    //  Import the registered Raw Card.
    //
    registered_card = vssc_card_manager_import_raw_card_with_initial_raw_card(
            card_manager, registered_raw_card, initial_raw_card, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REGISTER_CARD_FAILED_IMPORT_FAILED);
        goto cleanup;
    }

    //
    //  Store inner credentials.
    //
    new_creds =
            vssq_messenger_creds_new_with_disown(username, vssc_card_identifier(registered_card), &card_private_key);
    vssq_messenger_auth_reset_creds(self, new_creds);
    vssq_messenger_auth_update_user(self, &registered_card);

cleanup:
    vscf_key_provider_destroy(&key_provider);
    vsc_str_mutable_release(&request_url);
    vscf_impl_destroy(&card_private_key);
    vsc_buffer_destroy(&card_identity_bytes);
    vsc_str_buffer_destroy(&card_identity);
    vssc_card_manager_destroy(&card_manager);
    vssc_raw_card_destroy(&initial_raw_card);
    vssc_raw_card_destroy(&registered_raw_card);
    vssc_json_object_destroy(&initial_raw_card_json);
    vssc_json_object_destroy(&register_raw_card_json);
    vssc_json_object_destroy(&registered_raw_card_json);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssc_http_response_destroy(&register_card_response);
    vssq_messenger_creds_destroy(&new_creds);

    return vssq_error_status(&error);
}

//
//  Authenticate existing user with a given credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_authenticate(vssq_messenger_auth_t *self, const vssq_messenger_creds_t *creds) {

    //
    //  Check input parameters.
    //
    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(creds);

    //
    //  Update credentials and tokens if needed.
    //
    vssq_messenger_auth_reset_creds(self, creds);

    vssq_status_t status = vssq_messenger_auth_refresh_virgil_jwt(self);
    if (status != vssq_status_SUCCESS) {
        return status;
    }

    status = vssq_messenger_auth_refresh_ejabberd_token(self);
    if (status != vssq_status_SUCCESS) {
        return status;
    }

    status = vssq_messenger_auth_fetch_self_card(self);

    return status;
}

//
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_is_authenticated(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->user != NULL && self->creds != NULL;
}

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_auth_user(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_is_authenticated(self));

    return self->user;
}

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_auth_user_modifiable(vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_is_authenticated(self));

    return self->user;
}

//
//  Return true if user credentials are defined.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_creds(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->creds != NULL;
}

//
//  Return user credentials.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_auth_creds(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    return self->creds;
}

//
//  Return user's private key from credentials.
//
//  Prerequisites: credentials are defined.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_auth_private_key(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    return vssq_messenger_creds_private_key(self->creds);
}

//
//  Check whether current credentials were backed up.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_backup_creds(const vssq_messenger_auth_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->creds);

    //
    //  Update Virgil JWT first.
    //
    const vssq_status_t status = vssq_messenger_auth_refresh_virgil_jwt(self);
    if (status != vssq_status_SUCCESS) {
        return status;
    }

    //
    //  Declare vars.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssk_error_t keyknox_sdk_error;
    vssk_error_reset(&keyknox_sdk_error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssc_string_list_t *keys = NULL;

    bool result = false;

    //
    //  Get available key names.
    //
    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_get_keys(
            keyknox_client, k_keyknox_root_messenger, k_keyknox_path_credentials, vssc_jwt_identity(self->virgil_jwt));

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            http_request, k_http_header_auth_type_virgil, vssc_jwt_as_string(self->virgil_jwt));

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    keys = vssk_keyknox_client_process_response_get_keys(http_response, &keyknox_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    result = vssc_string_list_contains(keys, k_keyknox_alias_sign_in);

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssc_string_list_destroy(&keys);

    return result;
}

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_backup_creds(const vssq_messenger_auth_t *self, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->user);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(pwd));

    //
    //  Update Virgil JWT first.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    error.status = vssq_messenger_auth_refresh_virgil_jwt(self);
    if (vssq_error_has_error(&error)) {
        return error.status;
    }

    //
    //  Get pwd digest.
    //
    vsc_buffer_t *pwd_digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);
    vscf_sha512_hash(vsc_str_as_data(pwd), pwd_digest);

    vsc_data_t sign_in_pwd = vsc_data_slice_beg(vsc_buffer_data(pwd_digest), 0, 32);
    vsc_data_t brain_key_pwd = vsc_data_slice_beg(vsc_buffer_data(pwd_digest), 32, 32);

    //
    //  Declare resources.
    //
    vscf_impl_t *brain_private_key = NULL;
    vsc_buffer_t *keyknox_meta = NULL;
    vsc_buffer_t *keyknox_value = NULL;

    //
    //  Store password to the messenger backend.
    //
    error.status = vssq_messenger_auth_reset_sign_in_password(self, sign_in_pwd);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Generate Brain Key.
    //
    brain_private_key = vssq_messenger_auth_generate_brain_key(self, brain_key_pwd, &error);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Pack credentials to be stored within KeyKnox.
    //
    keyknox_meta = vsc_buffer_new();
    keyknox_value = vsc_buffer_new();

    error.status = vssq_messenger_auth_keyknox_pack_creds(self, brain_private_key, keyknox_meta, keyknox_value);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Push encrypted credentials to the Keyknox.
    //
    error.status =
            vssq_messenger_auth_keyknox_push_creds(self, vsc_buffer_data(keyknox_meta), vsc_buffer_data(keyknox_value));
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

cleanup:

    vsc_buffer_destroy(&pwd_digest);
    vscf_impl_destroy(&brain_private_key);
    vsc_buffer_destroy(&keyknox_meta);
    vsc_buffer_destroy(&keyknox_value);

    return vssq_error_status(&error);
}

//
//  Restore credentials from the backup and authenticate user.
//
//  Perform next steps:
//    1. Get base JWT using part of pwd.
//    2. Pull encrypted credentials from the Keyknox.
//    3. Decrypt credentials using another part of pwd.
//    4. Use credentials to authenticate within XMPP server (Ejabberd).
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_restore_creds(vssq_messenger_auth_t *self, vsc_str_t username, vsc_str_t pwd) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(pwd));

    //
    //  Get pwd digest.
    //
    vsc_buffer_t *pwd_digest = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);
    vscf_sha512_hash(vsc_str_as_data(pwd), pwd_digest);

    vsc_data_t sign_in_pwd = vsc_data_slice_beg(vsc_buffer_data(pwd_digest), 0, 32);
    vsc_data_t brain_key_pwd = vsc_data_slice_beg(vsc_buffer_data(pwd_digest), 32, 32);

    //
    //  Declare resources.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vscf_impl_t *brain_private_key = NULL;
    vscf_impl_t *brain_public_key = NULL;

    vsc_buffer_t *keyknox_meta = NULL;
    vsc_buffer_t *keyknox_value = NULL;

    vssq_messenger_creds_t *restored_creds = NULL;

    //
    //  Get Virgil JWT based on the password.
    //
    error.status = vssq_messenger_auth_refresh_virgil_jwt_with_password(self, username, sign_in_pwd);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }
    VSSQ_ASSERT(!vssc_jwt_is_expired(self->virgil_jwt));

    //
    //  Generate Brain Key.
    //
    brain_private_key = vssq_messenger_auth_generate_brain_key(self, brain_key_pwd, &error);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Pull encrypted credentials from the Keyknox.
    //
    keyknox_meta = vsc_buffer_new();
    keyknox_value = vsc_buffer_new();
    error.status = vssq_messenger_auth_keyknox_pull_creds(self, keyknox_meta, keyknox_value);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Unpack credentials from the KeyKnox.
    //
    restored_creds = vssq_messenger_auth_keyknox_unpack_creds(
            self, username, brain_private_key, vsc_buffer_data(keyknox_meta), vsc_buffer_data(keyknox_value), &error);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    //
    //  Preserve base token before reset credentials, as they will be destroyed.
    //
    vssc_jwt_t *stored_jwt = vssc_jwt_shallow_copy(self->virgil_jwt);
    vssq_messenger_auth_reset_creds(self, restored_creds);
    vssq_messenger_auth_reset_virgil_jwt(self, &stored_jwt);

    //
    //  Fetch our Virgil Card.
    //
    error.status = vssq_messenger_auth_fetch_self_card(self);
    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

cleanup:
    vsc_buffer_destroy(&pwd_digest);
    vscf_impl_destroy(&brain_private_key);
    vscf_impl_destroy(&brain_public_key);
    vsc_buffer_destroy(&keyknox_meta);
    vsc_buffer_destroy(&keyknox_value);
    vssq_messenger_creds_destroy(&restored_creds);

    return error.status;
}

//
//  Remove credentials backup from the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_remove_creds_backup(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_string_list_t *keyknox_identities = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;

    vsc_str_t identity = vssc_jwt_identity(self->virgil_jwt);

    //
    //  Reset previous record.
    //
    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_reset(
            keyknox_client, k_keyknox_root_messenger, k_keyknox_path_credentials, k_keyknox_alias_sign_in, identity);

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_string_list_destroy(&keyknox_identities);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssk_keyknox_entry_destroy(&keyknox_entry);

    return error.status;
}

//
//  Get JWT to use with Virgil services based on the credentials.
//
//  Prerequisites: user should be authenticated.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC const vssc_jwt_t *
vssq_messenger_auth_virgil_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->creds);

    const vssq_status_t status = vssq_messenger_auth_refresh_virgil_jwt(self);

    if (status == vssq_status_SUCCESS) {
        VSSQ_ASSERT_PTR(self->virgil_jwt);
        return self->virgil_jwt;

    } else {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }
}

//
//  Get JWT to use with Virgil Contact Discovery service based on the credentials.
//
//  Prerequisites: user should be authenticated.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC const vssc_jwt_t *
vssq_messenger_auth_contact_discovery_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->creds);

    const vssq_status_t status = vssq_messenger_auth_refresh_contact_discovery_jwt(self);

    if (status == vssq_status_SUCCESS) {
        VSSQ_ASSERT_PTR(self->virgil_jwt);
        return self->virgil_jwt;

    } else {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }
}

//
//  Return JWT to access ejabberd server.
//
//  Format: https://docs.ejabberd.im/admin/configuration/authentication/#jwt-authentication
//
//  Prerequisites: user should be authenticated.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC const vssq_ejabberd_jwt_t *
vssq_messenger_auth_ejabberd_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->creds);

    const vssq_status_t status = vssq_messenger_auth_refresh_ejabberd_token(self);

    if (status == vssq_status_SUCCESS) {
        VSSQ_ASSERT_PTR(self->ejabberd_jwt);
        return self->ejabberd_jwt;

    } else {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }
}

//
//  Reset credentials and invalidate cache if credentials are new.
//
static void
vssq_messenger_auth_reset_creds(vssq_messenger_auth_t *self, const vssq_messenger_creds_t *creds) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(creds);

    vssq_messenger_creds_delete(self->creds);
    vssc_jwt_destroy(&self->virgil_jwt);
    vssq_ejabberd_jwt_destroy(&self->ejabberd_jwt);
    self->creds = vssq_messenger_creds_shallow_copy_const(creds);
}

//
//  Get JWT to use with Virgil Services based on the password.
//
//  Note, cache is not used.
//
static vssq_status_t
vssq_messenger_auth_refresh_virgil_jwt_with_password(
        const vssq_messenger_auth_t *self, vsc_str_t username, vsc_data_t pwd) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(pwd));
    VSSQ_ASSERT(pwd.len == 32);

    //
    //  Declare result vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_json_object_t *token_json = NULL;
    vssc_http_response_t *http_response = NULL;

    vsc_str_buffer_t *auth_header_value = NULL;

    //
    //  Prepare request.
    //
    vsc_str_mutable_t url =
            vsc_str_mutable_concat(vssq_messenger_config_messenger_url(self->config), k_url_path_pwd_virgil_jwt);

    vssc_http_request_t *http_request =
            vssc_http_request_new_with_url(vssc_http_request_method_post, vsc_str_mutable_as_str(url));

    vsc_str_mutable_release(&url);

    const size_t auth_header_value_len =
            vssq_messenger_auth_USERNAME_DIGEST_LEN + 1 /* . */ + vscf_base64_encoded_len(pwd.len);

    auth_header_value = vsc_str_buffer_new_with_capacity(auth_header_value_len);

    error.status = vssq_contact_utils_hash_username(username, auth_header_value);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    vsc_str_buffer_write_char(auth_header_value, '.');
    vscf_base64_encode(pwd, &auth_header_value->buffer);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            http_request, k_http_header_auth_type_virgil_msg_pwd, vsc_str_buffer_str(auth_header_value));

    //
    //  Send.
    //
    http_response = vssq_messenger_auth_send_messenger_request(self, http_request, false, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    //
    //  Get token.
    //
    token_json = vssc_json_object_parse(vssc_http_response_body(http_response), &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    vsc_str_t token_str = vssc_json_object_get_string_value(token_json, k_json_key_token, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    //
    //  Parse Virgil JWT.
    //
    vssc_jwt_t *new_jwt = vssc_jwt_parse(token_str, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    vssq_messenger_auth_reset_virgil_jwt(self, &new_jwt);

cleanup:
    vsc_str_buffer_destroy(&auth_header_value);
    vssc_json_object_destroy(&token_json);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

    return vssq_error_status(&error);
}

//
//  Request Virgil JWt, Ejabberd JWT, or Virgil Contact Discovery JWT depends on the given endpoint.
//
static vssq_status_t
vssq_messenger_auth_request_token(const vssq_messenger_auth_t *self, vsc_str_t endpoint, vsc_str_buffer_t *jwt_str) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(endpoint));
    VSSQ_ASSERT(vsc_str_buffer_is_valid(jwt_str));

    //
    //  Declare resources.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vsc_str_mutable_t auth_url = {NULL, 0};

    //
    //  Request token.
    //
    auth_url = vsc_str_mutable_concat(vssq_messenger_config_messenger_url(self->config), endpoint);

    http_request = vssc_http_request_new_with_url(vssc_http_request_method_post, vsc_str_mutable_as_str(auth_url));

    http_response = vssq_messenger_auth_send_messenger_request(self, http_request, true, &error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    //
    //  Extract token from the response.
    //
    if (!vssc_http_response_body_is_json_object(http_response)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    vsc_str_t token_str = vssc_json_object_get_string_value(
            vssc_http_response_body_as_json_object(http_response), k_json_key_token, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    vsc_str_buffer_write_str(jwt_str, token_str);

cleanup:
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vsc_str_mutable_release(&auth_url);

    return vssq_error_status(&error);
}

//
//  Refresh Virgil Contact Discovery JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_virgil_jwt(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);

    //
    //  Check if the current token is up to date, i.e. was received via password authentication.
    //
    if (self->virgil_jwt && !vssc_jwt_is_expired(self->virgil_jwt)) {
        return vssq_status_SUCCESS;
    }

    //
    //  At this point we need credentials.
    //
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    //
    //  Request a new Virgil JWT.
    //
    vsc_str_buffer_t *virgil_jwt_str = vsc_str_buffer_new_with_capacity(vssq_messenger_auth_VIRGIL_JWT_LEN_MAX);

    const vssq_status_t status = vssq_messenger_auth_request_token(self, k_url_path_virgil_jwt, virgil_jwt_str);
    if (status != vssq_status_SUCCESS) {
        vsc_str_buffer_destroy(&virgil_jwt_str);
        return status;
    }

    //
    //  Parse Virgil JWT.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_jwt_t *virgil_jwt = vssc_jwt_parse(vsc_str_buffer_str(virgil_jwt_str), &core_sdk_error);
    vsc_str_buffer_destroy(&virgil_jwt_str);

    vssq_messenger_auth_reset_virgil_jwt(self, &virgil_jwt);

    if (!vssc_error_has_error(&core_sdk_error)) {
        return vssq_status_SUCCESS;
    } else {
        return vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED;
    }
}

//
//  Refresh Virgil JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_contact_discovery_jwt(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    //
    //  Check if the current token is up to date.
    //
    if (self->contact_discovery_jwt && !vssc_jwt_is_expired(self->contact_discovery_jwt)) {
        return vssq_status_SUCCESS;
    }

    //
    //  Request a new Virgil Contact Discovery JWT.
    //
    vsc_str_buffer_t *jwt_str = vsc_str_buffer_new_with_capacity(vssq_messenger_auth_CONTACT_DISCOVERY_JWT_LEN_MAX);

    const vssq_status_t status = vssq_messenger_auth_request_token(self, k_url_path_contact_discovery_jwt, jwt_str);
    if (status != vssq_status_SUCCESS) {
        vsc_str_buffer_destroy(&jwt_str);
        return status;
    }

    //
    //  Parse Virgil Contact Discovery JWT.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_jwt_t *jwt = vssc_jwt_parse(vsc_str_buffer_str(jwt_str), &core_sdk_error);
    vsc_str_buffer_destroy(&jwt_str);

    vssq_messenger_auth_reset_contact_discovery_jwt(self, &jwt);

    if (!vssc_error_has_error(&core_sdk_error)) {
        return vssq_status_SUCCESS;
    } else {
        return vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED;
    }
}

//
//  Refresh Ejabberd JWT if it absent or expired.
//
static vssq_status_t
vssq_messenger_auth_refresh_ejabberd_token(const vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    //
    //  Check if the current token is up to date.
    //
    if (self->ejabberd_jwt && !vssq_ejabberd_jwt_is_expired(self->ejabberd_jwt)) {
        return vssq_status_SUCCESS;
    }

    //
    //  Request a new Virgil JWT.
    //
    vsc_str_buffer_t *ejabberd_jwt_str = vsc_str_buffer_new_with_capacity(vssq_messenger_auth_EJABBERD_JWT_LEN_MAX);

    const vssq_status_t status = vssq_messenger_auth_request_token(self, k_url_path_ejabberd_jwt, ejabberd_jwt_str);
    if (status != vssq_status_SUCCESS) {
        vsc_str_buffer_destroy(&ejabberd_jwt_str);
        return status;
    }

    //
    //  Parse Ejabberd JWT.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssq_ejabberd_jwt_t *ejabberd_jwt = vssq_ejabberd_jwt_parse(vsc_str_buffer_str(ejabberd_jwt_str), &error);
    vsc_str_buffer_destroy(&ejabberd_jwt_str);

    vssq_messenger_auth_reset_ejabberd_jwt(self, &ejabberd_jwt);

    if (!vssq_error_has_error(&error)) {
        return vssq_status_SUCCESS;
    } else {
        return vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED;
    }
}

//
//  Set a new password to the messenger backend to get Virgil JWT when try to restore the key.
//
//  Note, password must be 32 bytes.
//
static vssq_status_t
vssq_messenger_auth_reset_sign_in_password(const vssq_messenger_auth_t *self, vsc_data_t pwd) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(pwd));
    VSSQ_ASSERT(pwd.len == 32);

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vsc_str_mutable_t auth_url = {NULL, 0};

    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;

    vssc_json_object_t *body_json = NULL;

    //
    //   Create request.
    //
    body_json = vssc_json_object_new();
    vssc_json_object_add_binary_value(body_json, k_json_key_password, pwd);

    auth_url = vsc_str_mutable_concat(vssq_messenger_config_messenger_url(self->config), k_url_path_set_password);
    http_request = vssc_http_request_new_with_body(
            vssc_http_request_method_post, vsc_str_mutable_as_str(auth_url), vssc_json_object_as_str(body_json));

    vssc_json_object_destroy(&body_json);

    vssc_http_request_add_header(
            http_request, vssc_http_header_name_content_type, vssc_http_header_value_application_json);


    http_response = vssq_messenger_auth_send_messenger_request(self, http_request, true, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_RESET_PASSWORD_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

cleanup:
    vsc_str_mutable_release(&auth_url);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssc_json_object_destroy(&body_json);

    return vssq_error_status(&error);
}

//
//  Use Pythia Service to generate private key that can decrypt the restored key.
//
//  Note, password must be 32 bytes.
//
static vscf_impl_t *
vssq_messenger_auth_generate_brain_key(const vssq_messenger_auth_t *self, vsc_data_t pwd, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->config);
    VSSQ_ASSERT_PTR(self->virgil_jwt);
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(pwd));
    VSSQ_ASSERT(pwd.len == 32);

    //
    //  Declare resources.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssp_error_t pythia_sdk_error;
    vssp_error_reset(&pythia_sdk_error);

    vscf_key_material_rng_t *key_material_rng = NULL;
    vscf_key_provider_t *key_provider = NULL;

    vscp_status_t pythia_status = vscp_status_SUCCESS;
    vssp_pythia_client_t *pythia_client = NULL;
    vssp_brain_key_seed_t *seed = NULL;

    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;

    vsc_buffer_t *blinded_password = NULL;
    vsc_buffer_t *blinding_secret = NULL;
    vsc_buffer_t *deblinded_password = NULL;

    vscf_impl_t *private_key = NULL;

    //
    //  Blind.
    //
    blinded_password = vsc_buffer_new_with_capacity(vscp_pythia_blinded_password_buf_len());

    blinding_secret = vsc_buffer_new_with_capacity(vscp_pythia_blinding_secret_buf_len());

    pythia_status = vscp_pythia_blind(pwd, blinded_password, blinding_secret);
    if (pythia_status != vscp_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_BRAINKEY_FAILED_BLIND_FAILED);
        goto cleanup;
    }

    //
    //  Get seed.
    //
    pythia_client = vssp_pythia_client_new();

    http_request = vssp_pythia_client_make_request_generate_seed(pythia_client, vsc_buffer_data(blinded_password));

    vsc_buffer_destroy(&blinded_password);

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_BRAINKEY_FAILED_SEED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    seed = vssp_pythia_client_process_response_generate_seed(http_response, &pythia_sdk_error);
    if (vssp_error_has_error(&pythia_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_BRAINKEY_FAILED_SEED_PARSE_FAILED);
        goto cleanup;
    }

    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

    deblinded_password = vsc_buffer_new_with_capacity(vscp_pythia_deblinded_password_buf_len());

    pythia_status =
            vscp_pythia_deblind(vssp_brain_key_seed_get(seed), vsc_buffer_data(blinding_secret), deblinded_password);

    if (pythia_status != vscp_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_BRAINKEY_FAILED_DEBLIND_FAILED);
        goto cleanup;
    }

    vsc_buffer_destroy(&blinding_secret);

    //
    // Generate key.
    //
    key_material_rng = vscf_key_material_rng_new();

    vscf_key_material_rng_reset_key_material(key_material_rng, vsc_buffer_data(deblinded_password));

    vsc_buffer_destroy(&deblinded_password);

    key_provider = vscf_key_provider_new();

    vscf_key_provider_use_random(key_provider, vscf_key_material_rng_impl(key_material_rng));

    private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, NULL);

    if (NULL == private_key) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_BRAINKEY_FAILED_CRYPTO_FAILED);
        goto cleanup;
    }

cleanup:
    vscf_key_material_rng_destroy(&key_material_rng);
    vscf_key_provider_destroy(&key_provider);
    vssp_pythia_client_destroy(&pythia_client);
    vssp_brain_key_seed_destroy(&seed);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vsc_buffer_destroy(&blinded_password);
    vsc_buffer_destroy(&blinding_secret);
    vsc_buffer_destroy(&deblinded_password);

    return private_key;
}

//
//  Encrypt credentials and put it to the Keyknox entries.
//
static vssq_status_t
vssq_messenger_auth_keyknox_pack_creds(const vssq_messenger_auth_t *self, const vscf_impl_t *brain_private_key,
        vsc_buffer_t *keyknox_meta, vsc_buffer_t *keyknox_value) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));
    VSSQ_ASSERT_PTR(brain_private_key);
    VSSQ_ASSERT_PTR(keyknox_meta);
    VSSQ_ASSERT_PTR(keyknox_value);

    //
    //  Declare vars.
    //
    vscf_impl_t *brain_public_key = NULL;
    vsc_buffer_t *exported_private_key = NULL;
    vscf_key_provider_t *key_provider = NULL;
    vscf_recipient_cipher_t *cipher = NULL;
    vssc_json_object_t *credentials_json = NULL;

    vscf_status_t foundation_status = vscf_status_SUCCESS;
    vssq_status_t status = vssq_status_SUCCESS;

    //
    //  Extract public key.
    //
    brain_public_key = vscf_private_key_extract_public_key(brain_private_key);

    //
    //  Export private key.
    //
    key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    const size_t exported_private_key_len =
            vscf_key_provider_exported_private_key_len(key_provider, vssq_messenger_creds_private_key(self->creds));

    exported_private_key = vsc_buffer_new_with_capacity(exported_private_key_len);

    foundation_status = vscf_key_provider_export_private_key(
            key_provider, vssq_messenger_creds_private_key(self->creds), exported_private_key);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_EXPORT_PRIVATE_KEY_FAILED;
        goto cleanup;
    }

    vscf_key_provider_destroy(&key_provider);

    //
    //  Pack Credentials.
    //  Format:
    //     {
    //         "version" : "v1"
    //         "card_id" : "HEX_STRING",
    //         "private_key" : "BASE64_STRING"
    //     }
    credentials_json = vssc_json_object_new();
    vssc_json_object_add_string_value(credentials_json, k_brain_key_json_version, k_brain_v1);
    vssc_json_object_add_string_value(
            credentials_json, k_brain_key_json_card_id, vssq_messenger_creds_card_id(self->creds));
    vssc_json_object_add_binary_value(
            credentials_json, k_brain_key_json_private_key, vsc_buffer_data(exported_private_key));

    vsc_data_t credentials_json_data = vsc_str_as_data(vssc_json_object_as_str(credentials_json));

    //
    //  Encrypt Credentials.
    //
    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);
    vscf_recipient_cipher_add_key_recipient(cipher, vsc_str_as_data(k_brain_key_recipient_id), brain_public_key);

    foundation_status =
            vscf_recipient_cipher_add_signer(cipher, vsc_str_as_data(k_brain_key_recipient_id), brain_private_key);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

    foundation_status = vscf_recipient_cipher_start_signed_encryption(cipher, credentials_json_data.len);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }


    vsc_buffer_reset_with_capacity(keyknox_meta, vscf_recipient_cipher_message_info_len(cipher));
    vscf_recipient_cipher_pack_message_info(cipher, keyknox_meta);

    vsc_buffer_reset_with_capacity(
            keyknox_value, vscf_recipient_cipher_encryption_out_len(cipher, credentials_json_data.len) +
                                   vscf_recipient_cipher_encryption_out_len(cipher, 0));

    foundation_status = vscf_recipient_cipher_process_encryption(cipher, credentials_json_data, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

    vssc_json_object_destroy(&credentials_json);

    foundation_status = vscf_recipient_cipher_finish_encryption(cipher, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

    const size_t footer_len = vscf_recipient_cipher_message_info_footer_len(cipher);
    vsc_buffer_reserve_unused(keyknox_value, footer_len);

    foundation_status = vscf_recipient_cipher_pack_message_info_footer(cipher, keyknox_value);

    if (foundation_status != vscf_status_SUCCESS) {
        status = vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED;
        goto cleanup;
    }

cleanup:
    vscf_impl_destroy(&brain_public_key);
    vsc_buffer_destroy(&exported_private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_recipient_cipher_destroy(&cipher);
    vssc_json_object_destroy(&credentials_json);

    return status;
}

//
//  Decrypt Keyknox entries and get credentials from it.
//
static vssq_messenger_creds_t *
vssq_messenger_auth_keyknox_unpack_creds(const vssq_messenger_auth_t *self, vsc_str_t username,
        const vscf_impl_t *brain_private_key, vsc_data_t keyknox_meta, vsc_data_t keyknox_value, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(brain_private_key);
    VSSQ_ASSERT(vsc_str_is_valid_and_non_empty(username));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(keyknox_meta));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(keyknox_value));

    //
    //  Declare vars.
    //
    vscf_impl_t *brain_public_key = NULL;
    vscf_recipient_cipher_t *cipher = NULL;
    vscf_key_provider_t *key_provider = NULL;
    vscf_impl_t *credentials_private_key = NULL;
    vssc_json_object_t *credentials_json = NULL;
    vsc_buffer_t *credentials_data = NULL;
    vsc_buffer_t *credentials_private_key_buf = NULL;
    vssq_messenger_creds_t *creds = NULL;

    //
    //  Decrypt Credentials.
    //
    vscf_status_t foundation_status = vscf_status_SUCCESS;

    cipher = vscf_recipient_cipher_new();
    vscf_recipient_cipher_use_random(cipher, self->random);

    foundation_status = vscf_recipient_cipher_start_decryption_with_key(
            cipher, vsc_str_as_data(k_brain_key_recipient_id), brain_private_key, keyknox_meta);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    credentials_data =
            vsc_buffer_new_with_capacity(vscf_recipient_cipher_decryption_out_len(cipher, keyknox_value.len) +
                                         vscf_recipient_cipher_decryption_out_len(cipher, 0));

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    foundation_status = vscf_recipient_cipher_process_decryption(cipher, keyknox_value, credentials_data);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    foundation_status = vscf_recipient_cipher_finish_decryption(cipher, credentials_data);

    if (foundation_status != vscf_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED);
        goto cleanup;
    }

    //
    //  Verify Credentials.
    //
    if (!vscf_recipient_cipher_is_data_signed(cipher)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    const vscf_signer_info_list_t *signer_infos = vscf_recipient_cipher_signer_infos(cipher);
    if (!vscf_signer_info_list_has_item(signer_infos)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    const vscf_signer_info_t *signer_info = vscf_signer_info_list_item(signer_infos);
    if (!vsc_data_equal(vsc_str_as_data(k_brain_key_recipient_id), vscf_signer_info_signer_id(signer_info))) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    brain_public_key = vscf_private_key_extract_public_key(brain_private_key);

    if (!vscf_recipient_cipher_verify_signer_info(cipher, signer_info, brain_public_key)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED);
        goto cleanup;
    }

    vscf_impl_destroy(&brain_public_key);
    vscf_recipient_cipher_destroy(&cipher);

    //
    //  Unpack Credentials.
    //  Format:
    //     {
    //         "version" : "v1"
    //         "card_id" : "HEX_STRING",
    //         "private_key" : "BASE64_STRING".
    //     }
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    credentials_json = vssc_json_object_parse(vsc_str_from_data(vsc_buffer_data(credentials_data)), &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    vsc_str_t credentials_version =
            vssc_json_object_get_string_value(credentials_json, k_brain_key_json_version, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    if (!vsc_str_equal(k_brain_v1, credentials_version)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    vsc_str_t card_id = vssc_json_object_get_string_value(credentials_json, k_brain_key_json_card_id, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    credentials_private_key_buf =
            vssc_json_object_get_binary_value_new(credentials_json, k_brain_key_json_private_key, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    //
    //  Import credentials.
    //
    key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, self->random);

    credentials_private_key =
            vscf_key_provider_import_private_key(key_provider, vsc_buffer_data(credentials_private_key_buf), NULL);

    if (NULL == credentials_private_key) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_IMPORT_PRIVATE_KEY_FAILED);
        goto cleanup;
    }

    creds = vssq_messenger_creds_new_with_disown(username, card_id, &credentials_private_key);

cleanup:
    vscf_impl_destroy(&brain_public_key);
    vscf_recipient_cipher_destroy(&cipher);
    vscf_key_provider_destroy(&key_provider);
    vssc_json_object_destroy(&credentials_json);
    vsc_buffer_destroy(&credentials_data);
    vsc_buffer_destroy(&credentials_private_key_buf);

    return creds;
}

//
//  Push Keyknox entries with credentials to the service.
//
static vssq_status_t
vssq_messenger_auth_keyknox_push_creds(
        const vssq_messenger_auth_t *self, vsc_data_t keyknox_meta, vsc_data_t keyknox_value) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(keyknox_meta));
    VSSQ_ASSERT(vsc_data_is_valid_and_non_empty(keyknox_value));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_string_list_t *keyknox_identities = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;

    vsc_str_t identity = vssc_jwt_identity(self->virgil_jwt);

    //
    //  Reset previous record.
    //
    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_reset(
            keyknox_client, k_keyknox_root_messenger, k_keyknox_path_credentials, k_keyknox_alias_sign_in, identity);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            http_request, k_http_header_auth_type_virgil, vssc_jwt_as_string(self->virgil_jwt));

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, &error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);

    //
    //  Push.
    //
    keyknox_identities = vssc_string_list_new();
    vssc_string_list_add(keyknox_identities, identity);

    keyknox_entry = vssk_keyknox_entry_new_with(k_keyknox_root_messenger, k_keyknox_path_credentials,
            k_keyknox_alias_sign_in, keyknox_identities, keyknox_meta, keyknox_value, vsc_data_empty());


    vssc_string_list_destroy(&keyknox_identities);

    http_request = vssk_keyknox_client_make_request_push(keyknox_client, keyknox_entry);

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, &error);

    if (NULL == http_response) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_string_list_destroy(&keyknox_identities);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssk_keyknox_entry_destroy(&keyknox_entry);

    return vssq_error_status(&error);
}

//
//  Pull Keyknox entries with credentials from the service.
//
static vssq_status_t
vssq_messenger_auth_keyknox_pull_creds(
        const vssq_messenger_auth_t *self, vsc_buffer_t *keyknox_meta, vsc_buffer_t *keyknox_value) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(keyknox_meta);
    VSSQ_ASSERT_PTR(keyknox_value);
    VSSQ_ASSERT_PTR(self->virgil_jwt);
    VSSQ_ASSERT(!vssc_jwt_is_expired(self->virgil_jwt));

    //
    //  Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssk_error_t keyknox_sdk_error;
    vssk_error_reset(&keyknox_sdk_error);

    vssk_keyknox_client_t *keyknox_client = NULL;
    vssc_http_request_t *http_request = NULL;
    vssc_http_response_t *http_response = NULL;
    vssk_keyknox_entry_t *keyknox_entry = NULL;

    //
    //  Pull encrypted credentials from the Keyknox.
    //
    keyknox_client = vssk_keyknox_client_new();

    http_request = vssk_keyknox_client_make_request_pull(keyknox_client, k_keyknox_root_messenger,
            k_keyknox_path_credentials, k_keyknox_alias_sign_in, vssc_jwt_identity(self->virgil_jwt));

    http_response = vssq_messenger_auth_send_virgil_request(self, http_request, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    keyknox_entry = vssk_keyknox_client_process_response_pull(http_response, &keyknox_sdk_error);

    if (!vssc_http_response_is_success(http_response)) {
        vssq_error_update(&error, vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED);
        goto cleanup;
    }

    vsc_buffer_reset_with_capacity(keyknox_meta, vssk_keyknox_entry_meta(keyknox_entry).len);
    vsc_buffer_write_data(keyknox_meta, vssk_keyknox_entry_meta(keyknox_entry));

    vsc_buffer_reset_with_capacity(keyknox_value, vssk_keyknox_entry_value(keyknox_entry).len);
    vsc_buffer_write_data(keyknox_value, vssk_keyknox_entry_value(keyknox_entry));

cleanup:
    vssk_keyknox_client_destroy(&keyknox_client);
    vssc_http_request_destroy(&http_request);
    vssc_http_response_destroy(&http_response);
    vssk_keyknox_entry_destroy(&keyknox_entry);

    return vssq_error_status(&error);
}

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_virgil_jwt(const vssq_messenger_auth_t *self, vssc_jwt_t **virgil_jwt_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(virgil_jwt_ref);

    VSSQ_ATOMIC_CRITICAL_SECTION_DECLARE(reset_virgil_jwt);
    VSSQ_ATOMIC_CRITICAL_SECTION_BEGIN(reset_virgil_jwt);

    vssq_messenger_auth_t *mutable_self = (vssq_messenger_auth_t *)self;

    vssc_jwt_destroy(&mutable_self->virgil_jwt);
    mutable_self->virgil_jwt = *virgil_jwt_ref;

    VSSQ_ATOMIC_CRITICAL_SECTION_END(reset_virgil_jwt);

    *virgil_jwt_ref = NULL;
}

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_contact_discovery_jwt(
        const vssq_messenger_auth_t *self, vssc_jwt_t **contact_discovery_jwt_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(contact_discovery_jwt_ref);

    VSSQ_ATOMIC_CRITICAL_SECTION_DECLARE(reset_contact_discovery_jwt);
    VSSQ_ATOMIC_CRITICAL_SECTION_BEGIN(reset_contact_discovery_jwt);

    vssq_messenger_auth_t *mutable_self = (vssq_messenger_auth_t *)self;

    vssc_jwt_destroy(&mutable_self->contact_discovery_jwt);
    mutable_self->contact_discovery_jwt = *contact_discovery_jwt_ref;

    VSSQ_ATOMIC_CRITICAL_SECTION_END(reset_contact_discovery_jwt);

    *contact_discovery_jwt_ref = NULL;
}

//
//  Method is thread-safe.
//
static void
vssq_messenger_auth_reset_ejabberd_jwt(const vssq_messenger_auth_t *self, vssq_ejabberd_jwt_t **ejabberd_jwt_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(ejabberd_jwt_ref);

    VSSQ_ATOMIC_CRITICAL_SECTION_DECLARE(reset_ejabberd_jwt);
    VSSQ_ATOMIC_CRITICAL_SECTION_BEGIN(reset_ejabberd_jwt);

    vssq_messenger_auth_t *mutable_self = (vssq_messenger_auth_t *)self;

    vssq_ejabberd_jwt_destroy(&mutable_self->ejabberd_jwt);
    mutable_self->ejabberd_jwt = *ejabberd_jwt_ref;

    VSSQ_ATOMIC_CRITICAL_SECTION_END(reset_ejabberd_jwt);

    *ejabberd_jwt_ref = NULL;
}

//
//  Fetch and store self card or error.
//
//  Prerequisites: user should be authenticated.
//  Prerequisites: Virgil JWT should be set and not expired.
//
static vssq_status_t
vssq_messenger_auth_fetch_self_card(vssq_messenger_auth_t *self) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->random);
    VSSQ_ASSERT_PTR(self->virgil_jwt);
    VSSQ_ASSERT(!vssc_jwt_is_expired(self->virgil_jwt));

    //
    // Declare vars.
    //
    vssq_error_t error;
    vssq_error_reset(&error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_card_manager_t *card_manager = NULL;
    vssc_card_client_t *card_client = NULL;
    vssc_http_request_t *get_card_request = NULL;
    vssc_http_response_t *get_cards_response = NULL;
    vssc_raw_card_t *founded_raw_card = NULL;
    vssc_card_t *founded_card = NULL;

    //
    //  Configure algorithms.
    //
    card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, self->random);

    core_sdk_error.status = vssc_card_manager_configure(card_manager);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_INIT_FAILED);
        goto cleanup;
    }

    //
    //  Send request.
    //
    card_client = vssc_card_client_new();

    get_card_request = vssc_card_client_make_request_get_card(card_client, vssq_messenger_creds_card_id(self->creds));

    get_cards_response = vssq_messenger_auth_send_virgil_request(self, get_card_request, &error);

    if (vssq_error_has_error(&error)) {
        goto cleanup;
    }

    if (vssc_http_response_status_code(get_cards_response) == 404) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_REQUIRED_NOT_FOUND);
        goto cleanup;
    }

    if (!vssc_http_response_is_success(get_cards_response)) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_RESPONSE_WITH_ERROR);
        goto cleanup;
    }

    founded_raw_card = vssc_card_client_process_response_get_card(get_cards_response, &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_PARSE_FAILED);
        goto cleanup;
    }

    if (vssc_raw_card_is_outdated(founded_raw_card)) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_REQUIRED_IS_OUTDATED);
        goto cleanup;
    }

    founded_card = vssc_card_manager_import_raw_card(card_manager, founded_raw_card, &core_sdk_error);
    if (vssc_error_has_error(&core_sdk_error)) {
        vssq_error_update(&error, vssq_status_SEARCH_CARD_FAILED_IMPORT_FAILED);
        goto cleanup;
    }

    vssq_messenger_auth_update_user(self, &founded_card);

cleanup:
    vssc_card_manager_destroy(&card_manager);
    vssc_card_client_destroy(&card_client);
    vssc_http_request_destroy(&get_card_request);
    vssc_http_response_destroy(&get_cards_response);
    vssc_raw_card_destroy(&founded_raw_card);

    return vssq_error_status(&error);
}

//
//  Create a new user based on the given card and credentials.
//
//  Prerequisites: user should be authenticated.
//
static void
vssq_messenger_auth_update_user(vssq_messenger_auth_t *self, vssc_card_t **card_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(self->creds);
    VSSQ_ASSERT_REF(card_ref);

    vssq_messenger_user_destroy(&self->user);

    self->user = vssq_messenger_user_new_with_card_disown(card_ref);
    vssq_messenger_user_set_username(self->user, vssq_messenger_creds_username(self->creds));
}

//
//  Send HTTP request to the a Virgil Messenger Backend.
//
//  Note, Authorization is added if "with auth" option is true.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_messenger_request(
        const vssq_messenger_auth_t *self, vssc_http_request_t *http_request, bool with_auth, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(http_request);
    VSSQ_ASSERT_PTR(self->random);

    //
    //  Set Messenger JWT first.
    //
    if (with_auth) {
        VSSQ_ASSERT_PTR(vssq_messenger_auth_has_creds(self));

        vscf_signer_t *signer = vscf_signer_new();
        vscf_signer_use_random(signer, self->random);
        vscf_signer_take_hash(signer, vscf_sha512_impl(vscf_sha512_new()));
        const size_t jwt_signature_len =
                vscf_signer_signature_len(signer, vssq_messenger_creds_private_key(self->creds));

        vsc_str_t card_id = vssq_messenger_creds_card_id(self->creds);

        char timestamp_str[22] = {'\0'};
        snprintf(timestamp_str, sizeof(timestamp_str) - 1, "%zu", vssc_unix_time_now());
        vsc_str_t timestamp = vsc_str_from_str(timestamp_str);

        const size_t jwt_signature_str_len = vscf_base64_encoded_len(jwt_signature_len);
        const size_t jwt_to_sign_len = card_id.len + 1 /* dot */ + timestamp.len;
        const size_t jwt_len = jwt_to_sign_len + 1 /* dot */ + jwt_signature_str_len;

        vsc_str_buffer_t *jwt = vsc_str_buffer_new_with_capacity(jwt_len);

        vsc_str_buffer_write_str(jwt, card_id);
        vsc_str_buffer_write_char(jwt, '.');
        vsc_str_buffer_write_str(jwt, timestamp);

        vsc_buffer_t *jwt_signature = vsc_buffer_new_with_capacity(jwt_signature_len);
        vscf_signer_reset(signer);
        vscf_signer_append_data(signer, vsc_str_as_data(vsc_str_buffer_str(jwt)));
        const vscf_status_t sign_status =
                vscf_signer_sign(signer, vssq_messenger_creds_private_key(self->creds), jwt_signature);

        if (sign_status == vscf_status_SUCCESS) {
            vsc_str_buffer_write_char(jwt, '.');
            vscf_base64_encode(vsc_buffer_data(jwt_signature), &(jwt->buffer));
        }

        vscf_signer_destroy(&signer);
        vsc_buffer_destroy(&jwt_signature);

        if (sign_status == vscf_status_SUCCESS) {
            vssc_http_request_set_auth_header_value_from_type_and_credentials(
                    http_request, k_http_header_auth_type_bearer, vsc_str_buffer_str(jwt));
            vsc_str_buffer_destroy(&jwt);

        } else {
            VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_GENERATE_AUTH_HEADER_FAILED);
            vsc_str_buffer_destroy(&jwt);
            return NULL;
        }
    }

    //
    //  Send request.
    //
    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_http_response_t *http_response = vssc_virgil_http_client_send_with_ca(
            http_request, vssq_messenger_config_ca_bundle(self->config), &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_HTTP_SEND_FAILED);
        return NULL;
    }

    return http_response;
}

//
//  Send HTTP request to the a Virgil Service, aka Cards, Keyknox etc.
//
//  Note, Virgil JWT is updated automatically.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_virgil_request(
        const vssq_messenger_auth_t *self, vssc_http_request_t *http_request, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(http_request);

    //
    //  Update Virgil JWT first.
    //
    const vssq_status_t status = vssq_messenger_auth_refresh_virgil_jwt(self);
    if (status != vssq_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            http_request, k_http_header_auth_type_virgil, vssc_jwt_as_string(self->virgil_jwt));

    vssc_http_response_t *http_response = vssc_virgil_http_client_send_with_ca(
            http_request, vssq_messenger_config_ca_bundle(self->config), &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_HTTP_SEND_FAILED);
        return NULL;
    }

    return http_response;
}

//
//  Send HTTP request to the a Virgil Contact Discovery Service.
//
//  Note, Contact Discovery JWT is updated automatically.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_contact_discovery_request(
        const vssq_messenger_auth_t *self, vssc_http_request_t *http_request, vssq_error_t *error) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(http_request);
    VSSQ_ASSERT(vssq_messenger_auth_has_creds(self));

    //
    //  Update Virgil Contact Discovery JWT first.
    //
    const vssq_status_t status = vssq_messenger_auth_refresh_contact_discovery_jwt(self);
    if (status != vssq_status_SUCCESS) {
        VSSQ_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_http_request_set_auth_header_value_from_type_and_credentials(http_request,
            k_http_header_auth_type_virgil_contact_discovery, vssc_jwt_as_string(self->contact_discovery_jwt));

    vssc_http_response_t *http_response = vssc_virgil_http_client_send_with_ca(
            http_request, vssq_messenger_config_ca_bundle(self->config), &core_sdk_error);

    if (vssc_error_has_error(&core_sdk_error)) {
        VSSQ_ERROR_SAFE_UPDATE(error, vssq_status_HTTP_SEND_FAILED);
        return NULL;
    }

    return http_response;
}
