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
//  This module contains 'message info der serializer' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_MESSAGE_INFO_DER_SERIALIZER_H_INCLUDED
#define VSCF_MESSAGE_INFO_DER_SERIALIZER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_message_info.h"
#include "vscf_error_ctx.h"
#include "vscf_impl.h"
#include "vscf_error.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
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
//  Public integral constants.
//
enum {
    vscf_message_info_der_serializer_PREFIX_LEN = 32
};

//
//  Handles implementation details.
//
typedef struct vscf_message_info_der_serializer_t vscf_message_info_der_serializer_t;

//
//  Return size of 'vscf_message_info_der_serializer_t' type.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_message_info_der_serializer_impl(vscf_message_info_der_serializer_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_init(vscf_message_info_der_serializer_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_init()'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_cleanup(vscf_message_info_der_serializer_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_message_info_der_serializer_t *
vscf_message_info_der_serializer_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_new()'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_delete(vscf_message_info_der_serializer_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_destroy(vscf_message_info_der_serializer_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_message_info_der_serializer_t *
vscf_message_info_der_serializer_shallow_copy(vscf_message_info_der_serializer_t *self);

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_use_asn1_reader(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_reader);

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_take_asn1_reader(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_reader);

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_release_asn1_reader(vscf_message_info_der_serializer_t *self);

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_use_asn1_writer(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_writer);

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_take_asn1_writer(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_writer);

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_release_asn1_writer(vscf_message_info_der_serializer_t *self);

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_message_info_der_serializer_setup_defaults(vscf_message_info_der_serializer_t *self);

//
//  Return buffer size enough to hold serialized message info.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_serialized_len(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info);

//
//  Serialize class "message info".
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_serialize(vscf_message_info_der_serializer_t *self,
        const vscf_message_info_t *message_info, vsc_buffer_t *out);

//
//  Read message info prefix from the given data, and if it is valid,
//  return a length of bytes of the whole message info.
//
//  Zero returned if length can not be determined from the given data,
//  and this means that there is no message info at the data beginning.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_read_prefix(vscf_message_info_der_serializer_t *self, vsc_data_t data);

//
//  Deserialize class "message info".
//
VSCF_PUBLIC vscf_message_info_t *
vscf_message_info_der_serializer_deserialize(vscf_message_info_der_serializer_t *self, vsc_data_t data,
        vscf_error_ctx_t *error);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_MESSAGE_INFO_DER_SERIALIZER_H_INCLUDED
//  @end
