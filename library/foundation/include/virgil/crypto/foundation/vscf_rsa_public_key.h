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
//  This module contains 'rsa public key' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_RSA_PUBLIC_KEY_H_INCLUDED
#define VSCF_RSA_PUBLIC_KEY_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_public_key.h"
#include "vscf_raw_public_key.h"
#include "vscf_status.h"
#include "vscf_alg_id.h"

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
typedef struct vscf_rsa_public_key_t vscf_rsa_public_key_t;

//
//  Return size of 'vscf_rsa_public_key_t' type.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_rsa_public_key_impl(vscf_rsa_public_key_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_rsa_public_key_impl_const(const vscf_rsa_public_key_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_rsa_public_key_init(vscf_rsa_public_key_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_rsa_public_key_init()'.
//
VSCF_PUBLIC void
vscf_rsa_public_key_cleanup(vscf_rsa_public_key_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_rsa_public_key_t *
vscf_rsa_public_key_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_public_key_new()'.
//
VSCF_PUBLIC void
vscf_rsa_public_key_delete(vscf_rsa_public_key_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_rsa_public_key_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_rsa_public_key_destroy(vscf_rsa_public_key_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_rsa_public_key_t *
vscf_rsa_public_key_shallow_copy(vscf_rsa_public_key_t *self);

//
//  Returns instance of the implemented interface 'public key'.
//
VSCF_PUBLIC const vscf_public_key_api_t *
vscf_rsa_public_key_public_key_api(void);

//
//  Return public key exponent.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_key_exponent(vscf_rsa_public_key_t *self);

//
//  Import public key from the raw binary format.
//
//  RSAPublicKey ::= SEQUENCE {
//      modulus INTEGER, -- n
//      publicExponent INTEGER -- e
//  }
//
VSCF_PRIVATE vscf_status_t
vscf_rsa_public_key_import(vscf_rsa_public_key_t *self, const vscf_raw_public_key_t *raw_public_key) VSCF_NODISCARD;

//
//  Export public key in the raw binary format.
//
//  RSAPublicKey ::= SEQUENCE {
//      modulus INTEGER, -- n
//      publicExponent INTEGER -- e
//  }
//
VSCF_PRIVATE vscf_raw_public_key_t *
vscf_rsa_public_key_export(const vscf_rsa_public_key_t *self);

//
//  Algorithm identifier the key belongs to.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_rsa_public_key_alg_id(const vscf_rsa_public_key_t *self);

//
//  Return algorithm information that can be used for serialization.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_rsa_public_key_alg_info(const vscf_rsa_public_key_t *self);

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_len(const vscf_rsa_public_key_t *self);

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_rsa_public_key_bitlen(const vscf_rsa_public_key_t *self);

//
//  Return tag of an associated algorithm that can handle this key.
//
VSCF_PRIVATE vscf_impl_tag_t
vscf_rsa_public_key_impl_tag(const vscf_rsa_public_key_t *self);

//
//  Check that key is valid.
//  Note, this operation can be slow.
//
VSCF_PUBLIC bool
vscf_rsa_public_key_is_valid(const vscf_rsa_public_key_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_RSA_PUBLIC_KEY_H_INCLUDED
//  @end
