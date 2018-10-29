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
//  This module contains 'rsa private key' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_RSA_PRIVATE_KEY_H_INCLUDED
#define VSCF_RSA_PRIVATE_KEY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_hash.h"
#include "vscf_error.h"

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
//  Handles implementation details.
//
typedef struct vscf_rsa_private_key_impl_t vscf_rsa_private_key_impl_t;

//
//  Return size of 'vscf_rsa_private_key_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_impl(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_rsa_private_key_init(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_init()'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_cleanup(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_rsa_private_key_impl_t *
vscf_rsa_private_key_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_new()'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_delete(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_private_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_rsa_private_key_destroy(vscf_rsa_private_key_impl_t **rsa_private_key_impl_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_rsa_private_key_impl_t *
vscf_rsa_private_key_copy(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Setup dependency to the interface api 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_hash(vscf_rsa_private_key_impl_t *rsa_private_key_impl, const vscf_hash_api_t *hash);

//
//  Release dependency to the interface api 'hash'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_hash(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_random(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1rd);

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1rd);

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_asn1rd(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_rsa_private_key_use_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1wr);

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_rsa_private_key_take_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vscf_impl_t *asn1wr);

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_rsa_private_key_release_asn1wr(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Setup parameters that is used during key generation.
//
VSCF_PUBLIC void
vscf_rsa_private_key_set_keygen_params(vscf_rsa_private_key_impl_t *rsa_private_key_impl, size_t bitlen,
        size_t exponent);

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_key_bitlen(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_generate_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_private_key_extract_public_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_decrypt(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data, vsc_buffer_t *out);

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_decrypted_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl, size_t data_len);

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_sign(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data, vsc_buffer_t *signature);

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_signature_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Export private key in the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_export_private_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_buffer_t *out);

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_rsa_private_key_exported_private_key_len(vscf_rsa_private_key_impl_t *rsa_private_key_impl);

//
//  Import private key from the binary format.
//
VSCF_PUBLIC vscf_error_t
vscf_rsa_private_key_import_private_key(vscf_rsa_private_key_impl_t *rsa_private_key_impl, vsc_data_t data);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RSA_PRIVATE_KEY_H_INCLUDED
//  @end
