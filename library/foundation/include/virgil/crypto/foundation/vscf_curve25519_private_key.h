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
//  This module contains 'curve25519 private key' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_CURVE25519_PRIVATE_KEY_H_INCLUDED
#define VSCF_CURVE25519_PRIVATE_KEY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_ecies.h"
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
    //  Define whether a private key can be imported or not.
    //
    vscf_curve25519_private_key_CAN_IMPORT_PRIVATE_KEY = true,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_curve25519_private_key_CAN_EXPORT_PRIVATE_KEY = true
};

//
//  Handles implementation details.
//
typedef struct vscf_curve25519_private_key_t vscf_curve25519_private_key_t;

//
//  Return size of 'vscf_curve25519_private_key_t' type.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_private_key_impl(vscf_curve25519_private_key_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_init(vscf_curve25519_private_key_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_curve25519_private_key_init()'.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_cleanup(vscf_curve25519_private_key_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_curve25519_private_key_t *
vscf_curve25519_private_key_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_curve25519_private_key_new()'.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_delete(vscf_curve25519_private_key_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_curve25519_private_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_destroy(vscf_curve25519_private_key_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_curve25519_private_key_t *
vscf_curve25519_private_key_shallow_copy(vscf_curve25519_private_key_t *self);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_use_random(vscf_curve25519_private_key_t *self, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_take_random(vscf_curve25519_private_key_t *self, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_release_random(vscf_curve25519_private_key_t *self);

//
//  Setup dependency to the implementation 'ecies' with shared ownership.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_use_ecies(vscf_curve25519_private_key_t *self, vscf_ecies_t *ecies);

//
//  Setup dependency to the implementation 'ecies' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_take_ecies(vscf_curve25519_private_key_t *self, vscf_ecies_t *ecies);

//
//  Release dependency to the implementation 'ecies'.
//
VSCF_PUBLIC void
vscf_curve25519_private_key_release_ecies(vscf_curve25519_private_key_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_setup_defaults(vscf_curve25519_private_key_t *self) VSCF_NODISCARD;

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_curve25519_private_key_alg_id(const vscf_curve25519_private_key_t *self);

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_private_key_produce_alg_info(const vscf_curve25519_private_key_t *self);

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_restore_alg_info(vscf_curve25519_private_key_t *self,
        const vscf_impl_t *alg_info) VSCF_NODISCARD;

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_key_len(const vscf_curve25519_private_key_t *self);

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_key_bitlen(const vscf_curve25519_private_key_t *self);

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_generate_key(vscf_curve25519_private_key_t *self) VSCF_NODISCARD;

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_decrypt(vscf_curve25519_private_key_t *self, vsc_data_t data,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_decrypted_len(vscf_curve25519_private_key_t *self, size_t data_len);

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_curve25519_private_key_extract_public_key(const vscf_curve25519_private_key_t *self);

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_export_private_key(const vscf_curve25519_private_key_t *self,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_exported_private_key_len(const vscf_curve25519_private_key_t *self);

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_import_private_key(vscf_curve25519_private_key_t *self, vsc_data_t data) VSCF_NODISCARD;

//
//  Compute shared key for 2 asymmetric keys.
//  Note, shared key can be used only for symmetric cryptography.
//
VSCF_PUBLIC vscf_status_t
vscf_curve25519_private_key_compute_shared_key(vscf_curve25519_private_key_t *self, const vscf_impl_t *public_key,
        vsc_buffer_t *shared_key) VSCF_NODISCARD;

//
//  Return number of bytes required to hold shared key.
//
VSCF_PUBLIC size_t
vscf_curve25519_private_key_shared_key_len(vscf_curve25519_private_key_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_CURVE25519_PRIVATE_KEY_H_INCLUDED
//  @end
