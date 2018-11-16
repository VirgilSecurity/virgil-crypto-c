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
//  Interface 'asn1 reader' API.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1_READER_API_H_INCLUDED
#define VSCF_ASN1_READER_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_error.h"

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
//  Callback. Reset all internal states and prepare to new ASN.1 reading operations.
//
typedef void (*vscf_asn1_reader_api_reset_fn)(vscf_impl_t *impl, vsc_data_t data);

//
//  Callback. Return last error.
//
typedef vscf_error_t (*vscf_asn1_reader_api_error_fn)(vscf_impl_t *impl);

//
//  Callback. Get tag of the current ASN.1 element.
//
typedef int (*vscf_asn1_reader_api_get_tag_fn)(vscf_impl_t *impl);

//
//  Callback. Get length of the current ASN.1 element.
//
typedef size_t (*vscf_asn1_reader_api_get_len_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: TAG.
//          Return element length.
//
typedef size_t (*vscf_asn1_reader_api_read_tag_fn)(vscf_impl_t *impl, int tag);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef int (*vscf_asn1_reader_api_read_int_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef int8_t (*vscf_asn1_reader_api_read_int8_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef int16_t (*vscf_asn1_reader_api_read_int16_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef int32_t (*vscf_asn1_reader_api_read_int32_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef int64_t (*vscf_asn1_reader_api_read_int64_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef unsigned int (*vscf_asn1_reader_api_read_uint_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef uint8_t (*vscf_asn1_reader_api_read_uint8_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef uint16_t (*vscf_asn1_reader_api_read_uint16_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef uint32_t (*vscf_asn1_reader_api_read_uint32_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: INTEGER.
//
typedef uint64_t (*vscf_asn1_reader_api_read_uint64_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: BOOLEAN.
//
typedef bool (*vscf_asn1_reader_api_read_bool_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: NULL.
//
typedef void (*vscf_asn1_reader_api_read_null_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: OCTET STRING.
//
typedef vsc_data_t (*vscf_asn1_reader_api_read_octet_str_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: UTF8String.
//
typedef vsc_data_t (*vscf_asn1_reader_api_read_utf8_str_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: OID.
//
typedef vsc_data_t (*vscf_asn1_reader_api_read_oid_fn)(vscf_impl_t *impl);

//
//  Callback. Read raw data of given length.
//
typedef vsc_data_t (*vscf_asn1_reader_api_read_data_fn)(vscf_impl_t *impl, size_t len);

//
//  Callback. Read ASN.1 type: CONSTRUCTED | SEQUENCE.
//          Return element length.
//
typedef size_t (*vscf_asn1_reader_api_read_sequence_fn)(vscf_impl_t *impl);

//
//  Callback. Read ASN.1 type: CONSTRUCTED | SET.
//          Return element length.
//
typedef size_t (*vscf_asn1_reader_api_read_set_fn)(vscf_impl_t *impl);

//
//  Contains API requirements of the interface 'asn1 reader'.
//
struct vscf_asn1_reader_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_reader' MUST be equal to the 'vscf_api_tag_ASN1_READER'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Reset all internal states and prepare to new ASN.1 reading operations.
    //
    vscf_asn1_reader_api_reset_fn reset_cb;
    //
    //  Return last error.
    //
    vscf_asn1_reader_api_error_fn error_cb;
    //
    //  Get tag of the current ASN.1 element.
    //
    vscf_asn1_reader_api_get_tag_fn get_tag_cb;
    //
    //  Get length of the current ASN.1 element.
    //
    vscf_asn1_reader_api_get_len_fn get_len_cb;
    //
    //  Read ASN.1 type: TAG.
    //  Return element length.
    //
    vscf_asn1_reader_api_read_tag_fn read_tag_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_int_fn read_int_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_int8_fn read_int8_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_int16_fn read_int16_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_int32_fn read_int32_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_int64_fn read_int64_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_uint_fn read_uint_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_uint8_fn read_uint8_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_uint16_fn read_uint16_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_uint32_fn read_uint32_cb;
    //
    //  Read ASN.1 type: INTEGER.
    //
    vscf_asn1_reader_api_read_uint64_fn read_uint64_cb;
    //
    //  Read ASN.1 type: BOOLEAN.
    //
    vscf_asn1_reader_api_read_bool_fn read_bool_cb;
    //
    //  Read ASN.1 type: NULL.
    //
    vscf_asn1_reader_api_read_null_fn read_null_cb;
    //
    //  Read ASN.1 type: OCTET STRING.
    //
    vscf_asn1_reader_api_read_octet_str_fn read_octet_str_cb;
    //
    //  Read ASN.1 type: UTF8String.
    //
    vscf_asn1_reader_api_read_utf8_str_fn read_utf8_str_cb;
    //
    //  Read ASN.1 type: OID.
    //
    vscf_asn1_reader_api_read_oid_fn read_oid_cb;
    //
    //  Read raw data of given length.
    //
    vscf_asn1_reader_api_read_data_fn read_data_cb;
    //
    //  Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    //  Return element length.
    //
    vscf_asn1_reader_api_read_sequence_fn read_sequence_cb;
    //
    //  Read ASN.1 type: CONSTRUCTED | SET.
    //  Return element length.
    //
    vscf_asn1_reader_api_read_set_fn read_set_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ASN1_READER_API_H_INCLUDED
//  @end
