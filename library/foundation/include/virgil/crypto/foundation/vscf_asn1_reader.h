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
//  Provides interface to the ASN.1 reader.
//  Note, that all "read" methods move reading position forward.
//  Note, that all "get" do not change reading position.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1_READER_H_INCLUDED
#define VSCF_ASN1_READER_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_status.h"
#include "vscf_api.h"

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
//  Contains API requirements of the interface 'asn1 reader'.
//
typedef struct vscf_asn1_reader_api_t vscf_asn1_reader_api_t;

//
//  Reset all internal states and prepare to new ASN.1 reading operations.
//
VSCF_PUBLIC void
vscf_asn1_reader_reset(vscf_impl_t *impl, vsc_data_t data);

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_asn1_reader_has_error(const vscf_impl_t *impl);

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_asn1_reader_status(const vscf_impl_t *impl);

//
//  Get tag of the current ASN.1 element.
//
VSCF_PUBLIC int
vscf_asn1_reader_get_tag(vscf_impl_t *impl);

//
//  Get length of the current ASN.1 element.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_get_len(vscf_impl_t *impl);

//
//  Get length of the current ASN.1 element with tag and length itself.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_get_data_len(vscf_impl_t *impl);

//
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_tag(vscf_impl_t *impl, int tag);

//
//  Read ASN.1 type: context-specific TAG.
//  Return element length.
//  Return 0 if current position do not points to the requested tag.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_context_tag(vscf_impl_t *impl, int tag);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1_reader_read_int(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int8_t
vscf_asn1_reader_read_int8(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int16_t
vscf_asn1_reader_read_int16(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int32_t
vscf_asn1_reader_read_int32(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int64_t
vscf_asn1_reader_read_int64(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC unsigned int
vscf_asn1_reader_read_uint(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint8_t
vscf_asn1_reader_read_uint8(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint16_t
vscf_asn1_reader_read_uint16(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint32_t
vscf_asn1_reader_read_uint32(vscf_impl_t *impl);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint64_t
vscf_asn1_reader_read_uint64(vscf_impl_t *impl);

//
//  Read ASN.1 type: BOOLEAN.
//
VSCF_PUBLIC bool
vscf_asn1_reader_read_bool(vscf_impl_t *impl);

//
//  Read ASN.1 type: NULL.
//
VSCF_PUBLIC void
vscf_asn1_reader_read_null(vscf_impl_t *impl);

//
//  Read ASN.1 type: OCTET STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_octet_str(vscf_impl_t *impl);

//
//  Read ASN.1 type: BIT STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_bitstring_as_octet_str(vscf_impl_t *impl);

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_utf8_str(vscf_impl_t *impl);

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_oid(vscf_impl_t *impl);

//
//  Read raw data of given length.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_data(vscf_impl_t *impl, size_t len);

//
//  Read ASN.1 type: CONSTRUCTED | SEQUENCE.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_sequence(vscf_impl_t *impl);

//
//  Read ASN.1 type: CONSTRUCTED | SET.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_set(vscf_impl_t *impl);

//
//  Return asn1 reader API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_asn1_reader_api_t *
vscf_asn1_reader_api(const vscf_impl_t *impl);

//
//  Check if given object implements interface 'asn1 reader'.
//
VSCF_PUBLIC bool
vscf_asn1_reader_is_implemented(const vscf_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_asn1_reader_api_tag(const vscf_asn1_reader_api_t *asn1_reader_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ASN1_READER_H_INCLUDED
//  @end
