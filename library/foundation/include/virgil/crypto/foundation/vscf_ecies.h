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
//  Virgil implementation of the ECIES algorithm.
// --------------------------------------------------------------------------

#ifndef VSCF_ECIES_H_INCLUDED
#define VSCF_ECIES_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

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
//  Handle 'ecies' context.
//
typedef struct vscf_ecies_t vscf_ecies_t;

//
//  Return size of 'vscf_ecies_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_ecies_init(vscf_ecies_t *self);

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_ecies_cleanup(vscf_ecies_t *self);

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_ecies_delete(vscf_ecies_t *self);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_ecies_new ()'.
//
VSCF_PUBLIC void
vscf_ecies_destroy(vscf_ecies_t **self_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_shallow_copy(vscf_ecies_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_random(vscf_ecies_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_random(vscf_ecies_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_ecies_release_random(vscf_ecies_t *self);

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_cipher(vscf_ecies_t *self, vscf_impl_t *cipher);

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_cipher(vscf_ecies_t *self, vscf_impl_t *cipher);

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_ecies_release_cipher(vscf_ecies_t *self);

//
//  Setup dependency to the interface 'mac' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_mac(vscf_ecies_t *self, vscf_impl_t *mac);

//
//  Setup dependency to the interface 'mac' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_mac(vscf_ecies_t *self, vscf_impl_t *mac);

//
//  Release dependency to the interface 'mac'.
//
VSCF_PUBLIC void
vscf_ecies_release_mac(vscf_ecies_t *self);

//
//  Setup dependency to the interface 'kdf' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_kdf(vscf_ecies_t *self, vscf_impl_t *kdf);

//
//  Setup dependency to the interface 'kdf' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_kdf(vscf_ecies_t *self, vscf_impl_t *kdf);

//
//  Release dependency to the interface 'kdf'.
//
VSCF_PUBLIC void
vscf_ecies_release_kdf(vscf_ecies_t *self);

//
//  Set ephemeral key that used for data encryption.
//  Public and ephemeral keys should belong to the same curve.
//  This dependency is optional.
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_ecies_use_ephemeral_key(vscf_ecies_t *self, vscf_impl_t *ephemeral_key);

//
//  Set ephemeral key that used for data encryption.
//  Public and ephemeral keys should belong to the same curve.
//  This dependency is optional.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_ephemeral_key(vscf_ecies_t *self, vscf_impl_t *ephemeral_key);

//
//  Release dependency to the interface 'private key'.
//
VSCF_PUBLIC void
vscf_ecies_release_ephemeral_key(vscf_ecies_t *self);

//
//  Set weak reference to the key algorithm.
//  Key algorithm MUST support shared key computation as well.
//
VSCF_PUBLIC void
vscf_ecies_set_key_alg(vscf_ecies_t *self, const vscf_impl_t *key_alg);

//
//  Release weak reference to the key algorithm.
//
VSCF_PUBLIC void
vscf_ecies_release_key_alg(vscf_ecies_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_setup_defaults(vscf_ecies_t *self) VSCF_NODISCARD;

//
//  Setup predefined values to the uninitialized class dependencies
//  except random.
//
VSCF_PUBLIC void
vscf_ecies_setup_defaults_no_random(vscf_ecies_t *self);

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_encrypted_len(const vscf_ecies_t *self, const vscf_impl_t *public_key, size_t data_len);

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_encrypt(const vscf_ecies_t *self, const vscf_impl_t *public_key, vsc_data_t data,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_decrypted_len(const vscf_ecies_t *self, const vscf_impl_t *private_key, size_t data_len);

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_decrypt(const vscf_ecies_t *self, const vscf_impl_t *private_key, vsc_data_t data,
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
#endif // VSCF_ECIES_H_INCLUDED
//  @end
