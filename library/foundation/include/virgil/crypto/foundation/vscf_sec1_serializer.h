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
//  This module contains 'sec1 serializer' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_SEC1_SERIALIZER_H_INCLUDED
#define VSCF_SEC1_SERIALIZER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_raw_key.h"
#include "vscf_error.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
typedef struct vscf_sec1_serializer_t vscf_sec1_serializer_t;

//
//  Return size of 'vscf_sec1_serializer_t' type.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sec1_serializer_impl(vscf_sec1_serializer_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_sec1_serializer_impl_const(const vscf_sec1_serializer_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_sec1_serializer_init(vscf_sec1_serializer_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_sec1_serializer_init()'.
//
VSCF_PUBLIC void
vscf_sec1_serializer_cleanup(vscf_sec1_serializer_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sec1_serializer_t *
vscf_sec1_serializer_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sec1_serializer_new()'.
//
VSCF_PUBLIC void
vscf_sec1_serializer_delete(vscf_sec1_serializer_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sec1_serializer_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sec1_serializer_destroy(vscf_sec1_serializer_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_sec1_serializer_t *
vscf_sec1_serializer_shallow_copy(vscf_sec1_serializer_t *self);

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_sec1_serializer_use_asn1_writer(vscf_sec1_serializer_t *self, vscf_impl_t *asn1_writer);

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_sec1_serializer_take_asn1_writer(vscf_sec1_serializer_t *self, vscf_impl_t *asn1_writer);

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_sec1_serializer_release_asn1_writer(vscf_sec1_serializer_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_sec1_serializer_setup_defaults(vscf_sec1_serializer_t *self);

//
//  Serialize Public Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialize_public_key_inplace(vscf_sec1_serializer_t *self, const vscf_raw_key_t *public_key,
        vscf_error_t *error);

//
//  Serialize Private Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialize_private_key_inplace(vscf_sec1_serializer_t *self, const vscf_raw_key_t *private_key,
        vscf_error_t *error);

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialized_public_key_len(vscf_sec1_serializer_t *self, const vscf_raw_key_t *public_key);

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_sec1_serializer_serialize_public_key(vscf_sec1_serializer_t *self, const vscf_raw_key_t *public_key,
        vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialized_private_key_len(vscf_sec1_serializer_t *self, const vscf_raw_key_t *private_key);

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_sec1_serializer_serialize_private_key(vscf_sec1_serializer_t *self, const vscf_raw_key_t *private_key,
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
#endif // VSCF_SEC1_SERIALIZER_H_INCLUDED
//  @end
