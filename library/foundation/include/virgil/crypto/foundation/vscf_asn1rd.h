//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
//  This module contains 'asn1rd' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1RD_H_INCLUDED
#define VSCF_ASN1RD_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"

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
typedef struct vscf_asn1rd_t vscf_asn1rd_t;

//
//  Return size of 'vscf_asn1rd_t' type.
//
VSCF_PUBLIC size_t
vscf_asn1rd_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_asn1rd_impl(vscf_asn1rd_t *self);

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_asn1rd_impl_const(const vscf_asn1rd_t *self);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_asn1rd_init(vscf_asn1rd_t *self);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_init()'.
//
VSCF_PUBLIC void
vscf_asn1rd_cleanup(vscf_asn1rd_t *self);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_asn1rd_t *
vscf_asn1rd_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_new()'.
//
VSCF_PUBLIC void
vscf_asn1rd_delete(vscf_asn1rd_t *self);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_asn1rd_destroy(vscf_asn1rd_t **self_ref);

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_asn1rd_t *
vscf_asn1rd_shallow_copy(vscf_asn1rd_t *self);

//
//  Reset all internal states and prepare to new ASN.1 reading operations.
//
VSCF_PUBLIC void
vscf_asn1rd_reset(vscf_asn1rd_t *self, vsc_data_t data);

//
//  Return length in bytes how many bytes are left for reading.
//
VSCF_PUBLIC size_t
vscf_asn1rd_left_len(vscf_asn1rd_t *self);

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_asn1rd_has_error(const vscf_asn1rd_t *self);

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_asn1rd_status(const vscf_asn1rd_t *self) VSCF_NODISCARD;

//
//  Get tag of the current ASN.1 element.
//
VSCF_PUBLIC int
vscf_asn1rd_get_tag(vscf_asn1rd_t *self);

//
//  Get length of the current ASN.1 element.
//
VSCF_PUBLIC size_t
vscf_asn1rd_get_len(vscf_asn1rd_t *self);

//
//  Get length of the current ASN.1 element with tag and length itself.
//
VSCF_PUBLIC size_t
vscf_asn1rd_get_data_len(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_tag(vscf_asn1rd_t *self, int tag);

//
//  Read ASN.1 type: context-specific TAG.
//  Return element length.
//  Return 0 if current position do not points to the requested tag.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_context_tag(vscf_asn1rd_t *self, int tag);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1rd_read_int(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int8_t
vscf_asn1rd_read_int8(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int16_t
vscf_asn1rd_read_int16(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int32_t
vscf_asn1rd_read_int32(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int64_t
vscf_asn1rd_read_int64(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC unsigned int
vscf_asn1rd_read_uint(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint8_t
vscf_asn1rd_read_uint8(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint16_t
vscf_asn1rd_read_uint16(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint32_t
vscf_asn1rd_read_uint32(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint64_t
vscf_asn1rd_read_uint64(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: BOOLEAN.
//
VSCF_PUBLIC bool
vscf_asn1rd_read_bool(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: NULL.
//
VSCF_PUBLIC void
vscf_asn1rd_read_null(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: NULL, only if it exists.
//  Note, this method is safe to call even no more data is left for reading.
//
VSCF_PUBLIC void
vscf_asn1rd_read_null_optional(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: OCTET STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_octet_str(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: BIT STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_bitstring_as_octet_str(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_utf8_str(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_oid(vscf_asn1rd_t *self);

//
//  Read raw data of given length.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_data(vscf_asn1rd_t *self, size_t len);

//
//  Read ASN.1 type: SEQUENCE.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_sequence(vscf_asn1rd_t *self);

//
//  Read ASN.1 type: SET.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_set(vscf_asn1rd_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ASN1RD_H_INCLUDED
//  @end
