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
//  This module contains 'pkcs8 der deserializer' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_PKCS8_DER_DESERIALIZER_H_INCLUDED
#define VSCF_PKCS8_DER_DESERIALIZER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_raw_key.h"
#include "vscf_impl.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
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
typedef struct vscf_pkcs8_der_deserializer_t vscf_pkcs8_der_deserializer_t;

//
//  Return size of 'vscf_pkcs8_der_deserializer_t' type.
//
VSCF_PUBLIC size_t
vscf_pkcs8_der_deserializer_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs8_der_deserializer_impl(vscf_pkcs8_der_deserializer_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_init(vscf_pkcs8_der_deserializer_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_der_deserializer_init()'.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_cleanup(vscf_pkcs8_der_deserializer_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_pkcs8_der_deserializer_t *
vscf_pkcs8_der_deserializer_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_der_deserializer_new()'.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_delete(vscf_pkcs8_der_deserializer_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_pkcs8_der_deserializer_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_destroy(vscf_pkcs8_der_deserializer_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_pkcs8_der_deserializer_t *
vscf_pkcs8_der_deserializer_shallow_copy(vscf_pkcs8_der_deserializer_t *self);

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_use_asn1_reader(vscf_pkcs8_der_deserializer_t *self, vscf_impl_t *asn1_reader);

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_take_asn1_reader(vscf_pkcs8_der_deserializer_t *self, vscf_impl_t *asn1_reader);

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_release_asn1_reader(vscf_pkcs8_der_deserializer_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_pkcs8_der_deserializer_setup_defaults(vscf_pkcs8_der_deserializer_t *self);

//
//  Deserialize Public Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_public_key_inplace(vscf_pkcs8_der_deserializer_t *self, vscf_error_t *error);

//
//  Deserialize Public Key by using internal ASN.1 reader.
//  Note, that caller code is responsible to reset ASN.1 reader with
//  an input buffer.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_private_key_inplace(vscf_pkcs8_der_deserializer_t *self, vscf_error_t *error);

//
//  Deserialize given public key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_public_key(vscf_pkcs8_der_deserializer_t *self, vsc_data_t public_key_data,
        vscf_error_t *error);

//
//  Deserialize given private key as an interchangeable format to the object.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_pkcs8_der_deserializer_deserialize_private_key(vscf_pkcs8_der_deserializer_t *self, vsc_data_t private_key_data,
        vscf_error_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_PKCS8_DER_DESERIALIZER_H_INCLUDED
//  @end
