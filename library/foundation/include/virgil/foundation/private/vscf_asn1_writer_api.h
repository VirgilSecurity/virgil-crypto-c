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
//  Interface 'asn1 writer' API.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1_WRITER_API_H_INCLUDED
#define VSCF_ASN1_WRITER_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_error.h"
#include "vscf_api.h"
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
//  Callback. Reset all internal states and prepare to new ASN.1 writing operations.
//
typedef void (*vscf_asn1_writer_api_reset_fn)(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Callback. Move written data to the buffer beginning and forbid further operations.
//
typedef void (*vscf_asn1_writer_api_seal_fn)(vscf_impl_t *impl);

//
//  Callback. Return last error.
//
typedef vscf_error_t (*vscf_asn1_writer_api_error_fn)(vscf_impl_t *impl);

//
//  Callback. Write ASN.1 tag.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_tag_fn)(vscf_impl_t *impl, int tag);

//
//  Callback. Write length of the following data.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_len_fn)(vscf_impl_t *impl, size_t len);

//
//  Callback. Write ASN.1 type: INTEGER.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_int_fn)(vscf_impl_t *impl, int value);

//
//  Callback. Write ASN.1 type: BOOLEAN.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_bool_fn)(vscf_impl_t *impl, bool value);

//
//  Callback. Write ASN.1 type: NULL.
//
typedef size_t (*vscf_asn1_writer_api_write_null_fn)(vscf_impl_t *impl);

//
//  Callback. Write ASN.1 type: OCTET STRING.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_octet_str_fn)(vscf_impl_t *impl, const vsc_data_t value);

//
//  Callback. Write ASN.1 type: UTF8String.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_utf8_str_fn)(vscf_impl_t *impl, const vsc_data_t value);

//
//  Callback. Write ASN.1 type: OID.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_oid_fn)(vscf_impl_t *impl, const vsc_data_t value);

//
//  Callback. Mark previously written data of given length as ASN.1 type: SQUENCE.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_sequence_fn)(vscf_impl_t *impl, size_t len);

//
//  Callback. Mark previously written data of given length as ASN.1 type: SET.
//          Return count of written bytes.
//
typedef size_t (*vscf_asn1_writer_api_write_set_fn)(vscf_impl_t *impl, size_t len);

//
//  Contains API requirements of the interface 'asn1 writer'.
//
struct vscf_asn1_writer_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_writer' MUST be equal to the 'vscf_api_tag_ASN1_WRITER'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Reset all internal states and prepare to new ASN.1 writing operations.
    //
    vscf_asn1_writer_api_reset_fn reset_cb;
    //
    //  Move written data to the buffer beginning and forbid further operations.
    //
    vscf_asn1_writer_api_seal_fn seal_cb;
    //
    //  Return last error.
    //
    vscf_asn1_writer_api_error_fn error_cb;
    //
    //  Write ASN.1 tag.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_tag_fn write_tag_cb;
    //
    //  Write length of the following data.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_len_fn write_len_cb;
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_int_fn write_int_cb;
    //
    //  Write ASN.1 type: BOOLEAN.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_bool_fn write_bool_cb;
    //
    //  Write ASN.1 type: NULL.
    //
    vscf_asn1_writer_api_write_null_fn write_null_cb;
    //
    //  Write ASN.1 type: OCTET STRING.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_octet_str_fn write_octet_str_cb;
    //
    //  Write ASN.1 type: UTF8String.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_utf8_str_fn write_utf8_str_cb;
    //
    //  Write ASN.1 type: OID.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_oid_fn write_oid_cb;
    //
    //  Mark previously written data of given length as ASN.1 type: SQUENCE.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_sequence_fn write_sequence_cb;
    //
    //  Mark previously written data of given length as ASN.1 type: SET.
    //  Return count of written bytes.
    //
    vscf_asn1_writer_api_write_set_fn write_set_cb;
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
#endif // VSCF_ASN1_WRITER_API_H_INCLUDED
//  @end
