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
//  This module contains 'round5' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_ROUND5_H_INCLUDED
#define VSCF_ROUND5_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_status.h"
#include "vscf_alg_id.h"
#include "vscf_raw_public_key.h"
#include "vscf_raw_private_key.h"

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
    vscf_round5_CAN_IMPORT_PUBLIC_KEY = true,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_round5_CAN_EXPORT_PUBLIC_KEY = true,
    //
    //  Define whether a private key can be imported or not.
    //
    vscf_round5_CAN_IMPORT_PRIVATE_KEY = true,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_round5_CAN_EXPORT_PRIVATE_KEY = true
};

//
//  Handles implementation details.
//
typedef struct vscf_round5_t vscf_round5_t;

//
//  Return size of 'vscf_round5_t' type.
//
VSCF_PUBLIC size_t
vscf_round5_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_impl(vscf_round5_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_round5_impl_const(const vscf_round5_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_round5_init(vscf_round5_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_round5_init()'.
//
VSCF_PUBLIC void
vscf_round5_cleanup(vscf_round5_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_round5_t *
vscf_round5_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_round5_new()'.
//
VSCF_PUBLIC void
vscf_round5_delete(vscf_round5_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_round5_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_round5_destroy(vscf_round5_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_round5_t *
vscf_round5_shallow_copy(vscf_round5_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_round5_use_random(vscf_round5_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_round5_take_random(vscf_round5_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_round5_release_random(vscf_round5_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_setup_defaults(vscf_round5_t *self) VSCF_NODISCARD;

//
//  Generate new private key.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_generate_key(const vscf_round5_t *self, vscf_error_t *error);

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_round5_alg_id(const vscf_round5_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_produce_alg_info(const vscf_round5_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_restore_alg_info(vscf_round5_t *self, const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_generate_ephemeral_key(const vscf_round5_t *self, const vscf_impl_t *key, vscf_error_t *error);

//
//  Import public key from the raw binary format.
//
//  Return public key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_import_public_key(const vscf_round5_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error);

//
//  Export public key to the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_public_key_t *
vscf_round5_export_public_key(const vscf_round5_t *self, const vscf_impl_t *public_key, vscf_error_t *error);

//
//  Import private key from the raw binary format.
//
//  Return private key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_impl_t *
vscf_round5_import_private_key(const vscf_round5_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error);

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_private_key_t *
vscf_round5_export_private_key(const vscf_round5_t *self, const vscf_impl_t *private_key, vscf_error_t *error);

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_round5_can_encrypt(const vscf_round5_t *self, const vscf_impl_t *public_key, size_t data_len);

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_round5_encrypted_len(const vscf_round5_t *self, const vscf_impl_t *public_key, size_t data_len);

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_encrypt(const vscf_round5_t *self, const vscf_impl_t *public_key, vsc_data_t data,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_round5_can_decrypt(const vscf_round5_t *self, const vscf_impl_t *private_key, size_t data_len);

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_round5_decrypted_len(const vscf_round5_t *self, const vscf_impl_t *private_key, size_t data_len);

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_round5_decrypt(const vscf_round5_t *self, const vscf_impl_t *private_key, vsc_data_t data,
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
#endif // VSCF_ROUND5_H_INCLUDED
//  @end
