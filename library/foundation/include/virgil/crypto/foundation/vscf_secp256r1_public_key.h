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
//  This module contains 'secp256r1 public key' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_SECP256R1_PUBLIC_KEY_H_INCLUDED
#define VSCF_SECP256R1_PUBLIC_KEY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_ecies.h"
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
//  Public integral constants.
//
enum {
    //
    //  Defines whether a public key can be imported or not.
    //
    vscf_secp256r1_public_key_CAN_IMPORT_PUBLIC_KEY = true,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_secp256r1_public_key_CAN_EXPORT_PUBLIC_KEY = true
};

//
//  Handles implementation details.
//
typedef struct vscf_secp256r1_public_key_t vscf_secp256r1_public_key_t;

//
//  Return size of 'vscf_secp256r1_public_key_t' type.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_public_key_impl(vscf_secp256r1_public_key_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_init(vscf_secp256r1_public_key_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_secp256r1_public_key_init()'.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_cleanup(vscf_secp256r1_public_key_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_secp256r1_public_key_t *
vscf_secp256r1_public_key_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_secp256r1_public_key_new()'.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_delete(vscf_secp256r1_public_key_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_secp256r1_public_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_destroy(vscf_secp256r1_public_key_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_secp256r1_public_key_t *
vscf_secp256r1_public_key_shallow_copy(vscf_secp256r1_public_key_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_use_random(vscf_secp256r1_public_key_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_take_random(vscf_secp256r1_public_key_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_release_random(vscf_secp256r1_public_key_t *self);

//
//  Setup dependency to the implementation 'ecies' with shared ownership.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_use_ecies(vscf_secp256r1_public_key_t *self, vscf_ecies_t *ecies);

//
//  Setup dependency to the implementation 'ecies' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_take_ecies(vscf_secp256r1_public_key_t *self, vscf_ecies_t *ecies);

//
//  Release dependency to the implementation 'ecies'.
//
VSCF_PUBLIC void
vscf_secp256r1_public_key_release_ecies(vscf_secp256r1_public_key_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_setup_defaults(vscf_secp256r1_public_key_t *self) VSCF_NODISCARD;

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_secp256r1_public_key_alg_id(const vscf_secp256r1_public_key_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_public_key_produce_alg_info(const vscf_secp256r1_public_key_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_restore_alg_info(vscf_secp256r1_public_key_t *self,
        const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_key_len(const vscf_secp256r1_public_key_t *self);

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_key_bitlen(const vscf_secp256r1_public_key_t *self);

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_encrypt(vscf_secp256r1_public_key_t *self, vsc_data_t data, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_encrypted_len(vscf_secp256r1_public_key_t *self, size_t data_len);

//
//  Verify data with given public key and signature.
//
VSCF_PUBLIC bool
vscf_secp256r1_public_key_verify_hash(vscf_secp256r1_public_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id,
        vsc_data_t signature);

//
//  Export public key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_export_public_key(const vscf_secp256r1_public_key_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PUBLIC size_t
vscf_secp256r1_public_key_exported_public_key_len(const vscf_secp256r1_public_key_t *self);

//
//  Import public key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_status_t
vscf_secp256r1_public_key_import_public_key(vscf_secp256r1_public_key_t *self, vsc_data_t data) VSCF_NODISCARD;

//
//  Generate ephemeral private key of the same type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_secp256r1_public_key_generate_ephemeral_key(vscf_secp256r1_public_key_t *self, vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_SECP256R1_PUBLIC_KEY_H_INCLUDED
//  @end
