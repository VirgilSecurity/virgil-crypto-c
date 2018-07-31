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
#include "vscf_error.h"
#include "vscf_impl.h"

#include <virgil/common/vsc_data.h>
#include <virgil/common/vsc_buffer.h>
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
vscf_asn1_reader_reset(vscf_impl_t *impl, const vsc_data_t data);

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1_reader_error(vscf_impl_t *impl);

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
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_tag(vscf_impl_t *impl, int tag);

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1_reader_read_int(vscf_impl_t *impl);

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
VSCF_PUBLIC void
vscf_asn1_reader_read_octet_str(vscf_impl_t *impl, vsc_buffer_t *value);

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC void
vscf_asn1_reader_read_utf8_str(vscf_impl_t *impl, vsc_buffer_t *value);

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC void
vscf_asn1_reader_read_oid(vscf_impl_t *impl, vsc_buffer_t *value);

//
//  Return asn1 reader API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_asn1_reader_api_t *
vscf_asn1_reader_api(vscf_impl_t *impl);

//
//  Check if given object implements interface 'asn1 reader'.
//
VSCF_PUBLIC bool
vscf_asn1_reader_is_implemented(vscf_impl_t *impl);


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
