//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
//  Class for client-side PHE crypto operations.
//  This class is thread-safe in case if VSCE_MULTI_THREAD defined
// --------------------------------------------------------------------------

#ifndef VSCE_PHE_CLIENT_H_INCLUDED
#define VSCE_PHE_CLIENT_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_error.h"

#if !VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if !VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCE_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

#if VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
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
//  Handle 'phe client' context.
//
typedef struct vsce_phe_client_t vsce_phe_client_t;

//
//  Return size of 'vsce_phe_client_t'.
//
VSCE_PUBLIC size_t
vsce_phe_client_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_client_init(vsce_phe_client_t *phe_client_ctx);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_client_cleanup(vsce_phe_client_t *phe_client_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_client_delete(vsce_phe_client_t *phe_client_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_client_new ()'.
//
VSCE_PUBLIC void
vsce_phe_client_destroy(vsce_phe_client_t **phe_client_ctx_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_client_t *
vsce_phe_client_copy(vsce_phe_client_t *phe_client_ctx);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_random(vsce_phe_client_t *phe_client_ctx);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_client_use_operation_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *operation_random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_client_take_operation_random(vsce_phe_client_t *phe_client_ctx, vscf_impl_t *operation_random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_client_release_operation_random(vsce_phe_client_t *phe_client_ctx);

//
//  Sets client private and server public key
//  Call this method before any other methods except `update enrollment record` and `generate client private key`
//  This function should be called only once
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_set_keys(vsce_phe_client_t *phe_client_ctx, vsc_data_t client_private_key,
        vsc_data_t server_public_key);

//
//  Generates client private key
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_generate_client_private_key(vsce_phe_client_t *phe_client_ctx, vsc_buffer_t *client_private_key);

//
//  Buffer size needed to fit EnrollmentRecord
//
VSCE_PUBLIC size_t
vsce_phe_client_enrollment_record_len(vsce_phe_client_t *phe_client_ctx);

//
//  Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
//  a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
//  Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_enroll_account(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_response, vsc_data_t password,
        vsc_buffer_t *enrollment_record, vsc_buffer_t *account_key);

//
//  Buffer size needed to fit VerifyPasswordRequest
//
VSCE_PUBLIC size_t
vsce_phe_client_verify_password_request_len(vsce_phe_client_t *phe_client_ctx);

//
//  Creates a request for further password verification at the PHE server side.
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_create_verify_password_request(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_buffer_t *verify_password_request);

//
//  Verifies PHE server's answer
//  If login succeeded, extracts account key
//  If login failed account key will be empty
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_check_response_and_decrypt(vsce_phe_client_t *phe_client_ctx, vsc_data_t password,
        vsc_data_t enrollment_record, vsc_data_t verify_password_response, vsc_buffer_t *account_key);

//
//  Updates client's private key and server's public key using server's update token
//  Use output values to instantiate new client instance with new keys
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_rotate_keys(vsce_phe_client_t *phe_client_ctx, vsc_data_t update_token,
        vsc_buffer_t *new_client_private_key, vsc_buffer_t *new_server_public_key);

//
//  Updates EnrollmentRecord using server's update token
//
VSCE_PUBLIC vsce_error_t
vsce_phe_client_update_enrollment_record(vsce_phe_client_t *phe_client_ctx, vsc_data_t enrollment_record,
        vsc_data_t update_token, vsc_buffer_t *new_enrollment_record);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_CLIENT_H_INCLUDED
//  @end
