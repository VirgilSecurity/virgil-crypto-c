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
//  Interface 'asn1_writer' API.
// --------------------------------------------------------------------------

#ifndef VSF_ASN1_WRITER_API_H_INCLUDED
#define VSF_ASN1_WRITER_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_api.h"
#include "vsf_impl.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Full defined types.
// ==========================================================================

//  Reset all internal states and prepare to new ASN.1 writing operations.
typedef int (*vsf_asn1_writer_api_reset_fn) (vsf_impl_t *impl, size_t capacity);

//  Returns the result ASN.1 structure.
typedef const byte * (*vsf_asn1_writer_api_finish_fn) (vsf_impl_t *impl);

//  Write ASN.1 type: INTEGER.
typedef int (*vsf_asn1_writer_api_write_int_fn) (vsf_impl_t *impl, int val);

//  Write ASN.1 type: BOOLEAN.
typedef int (*vsf_asn1_writer_api_write_bool_fn) (vsf_impl_t *impl, int val);

//  Write ASN.1 type: NULL.
typedef int (*vsf_asn1_writer_api_write_null_fn) (vsf_impl_t *impl);

//  Write ASN.1 type: OCTET STRING.
typedef int (*vsf_asn1_writer_api_write_octet_string_fn) (vsf_impl_t *impl, const byte *data);

//  Write ASN.1 type: UTF8String.
typedef int (*vsf_asn1_writer_api_write_utf8_string_fn) (vsf_impl_t *impl, const byte *data);

//  Write ASN.1 type: UTF8String.
typedef int (*vsf_asn1_writer_api_write_tag_fn) (vsf_impl_t *impl, size_t tag);

//  Write preformatted ASN.1 structure.
typedef int (*vsf_asn1_writer_api_write_data_fn) (vsf_impl_t *impl, const byte *data);

//  Write ASN.1 type: OID.
typedef int (*vsf_asn1_writer_api_write_oid_fn) (vsf_impl_t *impl, const byte *oid);

//  Write ASN.1 type: SEQUENCE.
typedef int (*vsf_asn1_writer_api_write_sequence_fn) (vsf_impl_t *impl, const byte *data);

//  Write ASN.1 type: SET OF ANY.
typedef int (*vsf_asn1_writer_api_write_set_fn) (vsf_impl_t *impl, const byte *ar, size_t ar_sz);

//  Interface 'asn1_writer' API.
struct vsf_asn1_writer_api_t {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_writer' MUST be equal to the 'vsf_api_tag_ASN1_WRITER'.
    vsf_api_tag_t api_tag;

    //  Reset all internal states and prepare to new ASN.1 writing operations.
    int (*reset_cb) (vsf_impl_t *impl, size_t capacity);

    //  Returns the result ASN.1 structure.
    const byte * (*finish_cb) (vsf_impl_t *impl);

    //  Write ASN.1 type: INTEGER.
    int (*write_int_cb) (vsf_impl_t *impl, int val);

    //  Write ASN.1 type: BOOLEAN.
    int (*write_bool_cb) (vsf_impl_t *impl, int val);

    //  Write ASN.1 type: NULL.
    int (*write_null_cb) (vsf_impl_t *impl);

    //  Write ASN.1 type: OCTET STRING.
    int (*write_octet_string_cb) (vsf_impl_t *impl, const byte *data);

    //  Write ASN.1 type: UTF8String.
    int (*write_utf8_string_cb) (vsf_impl_t *impl, const byte *data);

    //  Write ASN.1 type: UTF8String.
    int (*write_tag_cb) (vsf_impl_t *impl, size_t tag);

    //  Write preformatted ASN.1 structure.
    int (*write_data_cb) (vsf_impl_t *impl, const byte *data);

    //  Write ASN.1 type: OID.
    int (*write_oid_cb) (vsf_impl_t *impl, const byte *oid);

    //  Write ASN.1 type: SEQUENCE.
    int (*write_sequence_cb) (vsf_impl_t *impl, const byte *data);

    //  Write ASN.1 type: SET OF ANY.
    int (*write_set_cb) (vsf_impl_t *impl, const byte *ar, size_t ar_sz);
};
typedef struct vsf_asn1_writer_api_t vsf_asn1_writer_api_t;


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_ASN1_WRITER_API_H_INCLUDED
//  @end
