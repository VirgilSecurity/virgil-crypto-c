//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  Provide functionality for private key generation and importing that
//  relies on the software default implementations.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_PROVIDER_H_INCLUDED
#define VSCF_KEY_PROVIDER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_status.h"
#include "vscf_alg_id.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
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
//  Handle 'key provider' context.
//
typedef struct vscf_key_provider_t vscf_key_provider_t;

//
//  Return size of 'vscf_key_provider_t'.
//
VSCF_PUBLIC size_t
vscf_key_provider_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_key_provider_init(vscf_key_provider_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_key_provider_cleanup(vscf_key_provider_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_key_provider_t *
vscf_key_provider_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_key_provider_delete(vscf_key_provider_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_key_provider_new ()'.
//
VSCF_PUBLIC void
vscf_key_provider_destroy(vscf_key_provider_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_key_provider_t *
vscf_key_provider_shallow_copy(vscf_key_provider_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_key_provider_use_random(vscf_key_provider_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_key_provider_take_random(vscf_key_provider_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_key_provider_release_random(vscf_key_provider_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_setup_defaults(vscf_key_provider_t *self) VSCF_NODISCARD;

//
//  Setup parameters that is used during RSA key generation.
//
VSCF_PUBLIC void
vscf_key_provider_set_rsa_params(vscf_key_provider_t *self, size_t bitlen);

//
//  Generate new private key with a given algorithm.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_private_key(vscf_key_provider_t *self, vscf_alg_id_t alg_id, vscf_error_t *error);

//
//  Generate new compound private key with given algorithms.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_compound_private_key(vscf_key_provider_t *self, vscf_alg_id_t cipher_alg_id,
        vscf_alg_id_t signer_alg_id, vscf_error_t *error);

//
//  Generate new chained private key with given algorithms.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_chained_private_key(vscf_key_provider_t *self, vscf_alg_id_t l1_alg_id,
        vscf_alg_id_t l2_alg_id, vscf_error_t *error);

//
//  Generate new compound private key with nested chained private keys.
//
//  Note, l2 algorithm identifiers can be NONE, in this case regular key
//  will be crated instead of chained key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_generate_compound_chained_private_key(vscf_key_provider_t *self, vscf_alg_id_t cipher_l1_alg_id,
        vscf_alg_id_t cipher_l2_alg_id, vscf_alg_id_t signer_l1_alg_id, vscf_alg_id_t signer_l2_alg_id,
        vscf_error_t *error);

//
//  Import private key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_private_key(vscf_key_provider_t *self, vsc_data_t key_data, vscf_error_t *error);

//
//  Import public key from the PKCS#8 format.
//
VSCF_PUBLIC vscf_impl_t *
vscf_key_provider_import_public_key(vscf_key_provider_t *self, vsc_data_t key_data, vscf_error_t *error);

//
//  Calculate buffer size enough to hold exported public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_provider_exported_public_key_len(vscf_key_provider_t *self, const vscf_impl_t *public_key);

//
//  Export given public key to the PKCS#8 DER format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_export_public_key(vscf_key_provider_t *self, const vscf_impl_t *public_key,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate buffer size enough to hold exported private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_provider_exported_private_key_len(vscf_key_provider_t *self, const vscf_impl_t *private_key);

//
//  Export given private key to the PKCS#8 or SEC1 DER format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_provider_export_private_key(vscf_key_provider_t *self, const vscf_impl_t *private_key,
        vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_KEY_PROVIDER_H_INCLUDED
//  @end
