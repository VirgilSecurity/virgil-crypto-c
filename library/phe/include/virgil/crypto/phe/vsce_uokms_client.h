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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Class implements UOKMS for client-side.
// --------------------------------------------------------------------------

#ifndef VSCE_UOKMS_CLIENT_H_INCLUDED
#define VSCE_UOKMS_CLIENT_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"
#include "vsce_status.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_random.h>

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
//  Handle 'uokms client' context.
//
#ifndef VSCE_UOKMS_CLIENT_T_DEFINED
#define VSCE_UOKMS_CLIENT_T_DEFINED
    typedef struct vsce_uokms_client_t vsce_uokms_client_t;
#endif // VSCE_UOKMS_CLIENT_T_DEFINED

//
//  Return size of 'vsce_uokms_client_t'.
//
VSCE_PUBLIC size_t
vsce_uokms_client_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_uokms_client_init(vsce_uokms_client_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_uokms_client_cleanup(vsce_uokms_client_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_uokms_client_t *
vsce_uokms_client_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_uokms_client_delete(const vsce_uokms_client_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_uokms_client_new ()'.
//
VSCE_PUBLIC void
vsce_uokms_client_destroy(vsce_uokms_client_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_uokms_client_t *
vsce_uokms_client_shallow_copy(vsce_uokms_client_t *self);

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCE_PUBLIC const vsce_uokms_client_t *
vsce_uokms_client_shallow_copy_const(const vsce_uokms_client_t *self);

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_client_use_random(vsce_uokms_client_t *self, vscf_impl_t *random);

//
//  Random used for key generation, proofs, etc.
//
//  Note, ownership is transferred.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_client_take_random(vsce_uokms_client_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_client_release_random(vsce_uokms_client_t *self);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_uokms_client_use_operation_random(vsce_uokms_client_t *self, vscf_impl_t *operation_random);

//
//  Random used for crypto operations to make them const-time
//
//  Note, ownership is transferred.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_uokms_client_take_operation_random(vsce_uokms_client_t *self, vscf_impl_t *operation_random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_uokms_client_release_operation_random(vsce_uokms_client_t *self);

//
//  Setups dependencies with default values.
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_setup_defaults(vsce_uokms_client_t *self) VSCE_NODISCARD;

//
//  Sets client private
//  Call this method before any other methods
//  This function should be called only once
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_set_keys_oneparty(vsce_uokms_client_t *self, vsc_data_t client_private_key) VSCE_NODISCARD;

//
//  Sets client private and server public key
//  Call this method before any other methods
//  This function should be called only once
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_set_keys(vsce_uokms_client_t *self, vsc_data_t client_private_key,
        vsc_data_t server_public_key) VSCE_NODISCARD;

//
//  Generates client private key
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_client_private_key(vsce_uokms_client_t *self,
        vsc_buffer_t *client_private_key) VSCE_NODISCARD;

//
//  Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
//  of "encryption key len" that can be used for symmetric encryption
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_encrypt_wrap(vsce_uokms_client_t *self, vsc_buffer_t *wrap, size_t encryption_key_len,
        vsc_buffer_t *encryption_key) VSCE_NODISCARD;

//
//  Decrypt
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_decrypt_oneparty(vsce_uokms_client_t *self, vsc_data_t wrap, size_t encryption_key_len,
        vsc_buffer_t *encryption_key) VSCE_NODISCARD;

//
//  Generates request to decrypt data, this request should be sent to the server.
//  Server response is then passed to "process decrypt response" where encryption key can be decapsulated
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_decrypt_request(vsce_uokms_client_t *self, vsc_data_t wrap, vsc_buffer_t *deblind_factor,
        vsc_buffer_t *decrypt_request) VSCE_NODISCARD;

//
//  Processed server response, checks server proof and decapsulates encryption key
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_process_decrypt_response(vsce_uokms_client_t *self, vsc_data_t wrap, vsc_data_t decrypt_request,
        vsc_data_t decrypt_response, vsc_data_t deblind_factor, size_t encryption_key_len,
        vsc_buffer_t *encryption_key) VSCE_NODISCARD;

//
//  Rotates client key using given update token obtained from server
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_rotate_keys_oneparty(vsce_uokms_client_t *self, vsc_data_t update_token,
        vsc_buffer_t *new_client_private_key) VSCE_NODISCARD;

//
//  Generates update token for one-party mode
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_generate_update_token_oneparty(vsce_uokms_client_t *self, vsc_buffer_t *update_token) VSCE_NODISCARD;

//
//  Rotates client and server keys using given update token obtained from server
//
VSCE_PUBLIC vsce_status_t
vsce_uokms_client_rotate_keys(vsce_uokms_client_t *self, vsc_data_t update_token, vsc_buffer_t *new_client_private_key,
        vsc_buffer_t *new_server_public_key) VSCE_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_UOKMS_CLIENT_H_INCLUDED
//  @end
