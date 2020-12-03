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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provides access to the messenger authentication endpoints.
// --------------------------------------------------------------------------

#ifndef VSSQ_MESSENGER_AUTH_H_INCLUDED
#define VSSQ_MESSENGER_AUTH_H_INCLUDED

#include "vssq_library.h"
#include "vssq_messenger_config.h"
#include "vssq_status.h"
#include "vssq_messenger_creds.h"
#include "vssq_messenger_user.h"
#include "vssq_error.h"
#include "vssq_ejabberd_jwt.h"

#include <virgil/crypto/foundation/vscf_random.h>

#if !VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_str.h>
#endif

#if !VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <virgil/sdk/core/vssc_http_response.h>
#   include <virgil/sdk/core/vssc_jwt.h>
#   include <virgil/sdk/core/vssc_http_request.h>
#   include <virgil/sdk/core/vssc_http_header.h>
#endif

#if !VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_str.h>
#endif

#if VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK
#   include <VSSC/vssc_http_header.h>
#   include <VSSC/vssc_jwt.h>
#   include <VSSC/vssc_http_request.h>
#   include <VSSC/vssc_http_response.h>
#endif

#if VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'messenger auth' context.
//
#ifndef VSSQ_MESSENGER_AUTH_T_DEFINED
#define VSSQ_MESSENGER_AUTH_T_DEFINED
    typedef struct vssq_messenger_auth_t vssq_messenger_auth_t;
#endif // VSSQ_MESSENGER_AUTH_T_DEFINED

//
//  Return size of 'vssq_messenger_auth_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_auth_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init(vssq_messenger_auth_t *self);

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_auth_cleanup(vssq_messenger_auth_t *self);

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new(void);

//
//  Perform initialization of pre-allocated context.
//  Initialize with a custom configuration.
//
VSSQ_PUBLIC void
vssq_messenger_auth_init_with_config(vssq_messenger_auth_t *self, const vssq_messenger_config_t *config);

//
//  Allocate class context and perform it's initialization.
//  Initialize with a custom configuration.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_new_with_config(const vssq_messenger_config_t *config);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_auth_delete(const vssq_messenger_auth_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_auth_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_destroy(vssq_messenger_auth_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy(vssq_messenger_auth_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_auth_t *
vssq_messenger_auth_shallow_copy_const(const vssq_messenger_auth_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSSQ_PUBLIC void
vssq_messenger_auth_use_random(vssq_messenger_auth_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSSQ_PUBLIC void
vssq_messenger_auth_take_random(vssq_messenger_auth_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSSQ_PUBLIC void
vssq_messenger_auth_release_random(vssq_messenger_auth_t *self);

//
//  Return configuration.
//
VSSQ_PUBLIC const vssq_messenger_config_t *
vssq_messenger_auth_config(const vssq_messenger_auth_t *self);

//
//  Register a new user with a given name.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_register(vssq_messenger_auth_t *self, vsc_str_t username) VSSQ_NODISCARD;

//
//  Authenticate existing user with a given credentials.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_authenticate(vssq_messenger_auth_t *self, const vssq_messenger_creds_t *creds) VSSQ_NODISCARD;

//
//  Return true if a user is authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_is_authenticated(const vssq_messenger_auth_t *self);

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC const vssq_messenger_user_t *
vssq_messenger_auth_user(const vssq_messenger_auth_t *self);

//
//  Return information about current user.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_messenger_user_t *
vssq_messenger_auth_user_modifiable(vssq_messenger_auth_t *self);

//
//  Return true if user credentials are defined.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_creds(const vssq_messenger_auth_t *self);

//
//  Return user credentials.
//
VSSQ_PUBLIC const vssq_messenger_creds_t *
vssq_messenger_auth_creds(const vssq_messenger_auth_t *self);

//
//  Return user's private key from credentials.
//
//  Prerequisites: credentials are defined.
//
VSSQ_PUBLIC const vscf_impl_t *
vssq_messenger_auth_private_key(const vssq_messenger_auth_t *self);

//
//  Check whether current credentials were backed up.
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC bool
vssq_messenger_auth_has_backup_creds(const vssq_messenger_auth_t *self, vssq_error_t *error);

//
//  Encrypt the user credentials and push them to the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_backup_creds(const vssq_messenger_auth_t *self, vsc_str_t pwd) VSSQ_NODISCARD;

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
vssq_messenger_auth_restore_creds(vssq_messenger_auth_t *self, vsc_str_t username, vsc_str_t pwd) VSSQ_NODISCARD;

//
//  Remove credentials backup from the secure cloud storage (Keyknox).
//
//  Prerequisites: user should be authenticated.
//
VSSQ_PUBLIC vssq_status_t
vssq_messenger_auth_remove_creds_backup(const vssq_messenger_auth_t *self) VSSQ_NODISCARD;

//
//  Get JWT to use with Virgil services based on the credentials.
//
//  Prerequisites: user should be authenticated.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC const vssc_jwt_t *
vssq_messenger_auth_virgil_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error);

//
//  Get JWT to use with Virgil Contact Discovery service based on the credentials.
//
//  Prerequisites: user should be authenticated.
//
//  Note, the cached token is returned if it is exist and not expired.
//
VSSQ_PUBLIC const vssc_jwt_t *
vssq_messenger_auth_contact_discovery_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error);

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
vssq_messenger_auth_ejabberd_jwt(const vssq_messenger_auth_t *self, vssq_error_t *error);

//
//  Generate authorization header for a Virgil Messenger Backend.
//
//  Header-Name : Authorization
//  Header-Value: Bearer JWT
//
//  Prerequisites: credentials are defined.
//
VSSQ_PUBLIC vssc_http_header_t *
vssq_messenger_auth_generate_messenger_auth_header(const vssq_messenger_auth_t *self, vssq_error_t *error);

//
//  Send HTTP request to the a Virgil Messenger Backend.
//
//  Note, Authorization is added if "with auth" option is true.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_messenger_request(const vssq_messenger_auth_t *self, vssc_http_request_t *http_request,
        bool with_auth, vssq_error_t *error);

//
//  Send HTTP request to the a Virgil Service, aka Cards, Keyknox etc.
//
//  Note, Virgil JWT is updated automatically.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_virgil_request(const vssq_messenger_auth_t *self, vssc_http_request_t *http_request,
        vssq_error_t *error);

//
//  Send HTTP request to the a Virgil Contact Discovery Service.
//
//  Note, Contact Discovery JWT is updated automatically.
//
VSSQ_PUBLIC vssc_http_response_t *
vssq_messenger_auth_send_contact_discovery_request(const vssq_messenger_auth_t *self, vssc_http_request_t *http_request,
        vssq_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSQ_MESSENGER_AUTH_H_INCLUDED
//  @end
