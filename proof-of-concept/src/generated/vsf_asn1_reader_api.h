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
//  Interface 'asn1_reader' API.
// --------------------------------------------------------------------------

#ifndef VSF_ASN1_READER_API_H_INCLUDED
#define VSF_ASN1_READER_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_api.h"
#include "vsf_impl.h"
//  @end


#include "vsf_buffer_api.h"


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

//  Reset all internal states and prepare to new ASN.1 reading operations.
typedef int (*vsf_asn1_reader_api_reset_fn) (vsf_impl_t *impl, const vsf_buffer_t *item);

//  Read ASN.1 type: INTEGER.
typedef int (*vsf_asn1_reader_api_read_int_fn) (vsf_impl_t *impl, int *val);

//  Read ASN.1 type: BOOLEAN.
typedef int (*vsf_asn1_reader_api_read_bool_fn) (vsf_impl_t *impl, int *val);

//  Read ASN.1 type: NULL.
typedef int (*vsf_asn1_reader_api_read_null_fn) (vsf_impl_t *impl);

//  Read ASN.1 type: OCTET STRING.
typedef int (*vsf_asn1_reader_api_read_octet_str_fn) (vsf_impl_t *impl, vsf_buffer_t *val);

//  Read ASN.1 type: UTF8String.
typedef int (*vsf_asn1_reader_api_read_utf8_str_fn) (vsf_impl_t *impl, const vsf_buffer_t *val);

//  Read preformatted ASN.1 structure.
typedef int (*vsf_asn1_reader_api_read_fn) (vsf_impl_t *impl, const vsf_buffer_t *val);

//  Read ASN.1 type: TAG.
typedef int (*vsf_asn1_reader_api_read_tag_fn) (vsf_impl_t *impl, size_t val);

//  Read ASN.1 type: OID.
typedef int (*vsf_asn1_reader_api_read_oid_fn) (vsf_impl_t *impl, const vsf_buffer_t *val);

//  Read ASN.1 type: SEQUENCE.
typedef int (*vsf_asn1_reader_api_read_sequence_fn) (vsf_impl_t *impl, size_t val);

//  Read ASN.1 type: SET.
typedef int (*vsf_asn1_reader_api_read_set_fn) (vsf_impl_t *impl, size_t val);

//  Interface 'asn1_reader' API.
struct vsf_asn1_reader_api_t {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_reader' MUST be equal to the 'vsf_api_tag_ASN1_READER'.
    vsf_api_tag_t api_tag;

    //  Reset all internal states and prepare to new ASN.1 reading operations.
    int (*reset_cb) (vsf_impl_t *impl, const vsf_buffer_t *item);

    //  Read ASN.1 type: INTEGER.
    int (*read_int_cb) (vsf_impl_t *impl, int *val);

    //  Read ASN.1 type: BOOLEAN.
    int (*read_bool_cb) (vsf_impl_t *impl, int *val);

    //  Read ASN.1 type: NULL.
    int (*read_null_cb) (vsf_impl_t *impl);

    //  Read ASN.1 type: OCTET STRING.
    int (*read_octet_str_cb) (vsf_impl_t *impl, vsf_buffer_t *val);

    //  Read ASN.1 type: UTF8String.
    int (*read_utf8_str_cb) (vsf_impl_t *impl, const vsf_buffer_t *val);

    //  Read preformatted ASN.1 structure.
    int (*read_cb) (vsf_impl_t *impl, const vsf_buffer_t *val);

    //  Read ASN.1 type: TAG.
    int (*read_tag_cb) (vsf_impl_t *impl, size_t val);

    //  Read ASN.1 type: OID.
    int (*read_oid_cb) (vsf_impl_t *impl, const vsf_buffer_t *val);

    //  Read ASN.1 type: SEQUENCE.
    int (*read_sequence_cb) (vsf_impl_t *impl, size_t val);

    //  Read ASN.1 type: SET.
    int (*read_set_cb) (vsf_impl_t *impl, size_t val);
};
typedef struct vsf_asn1_reader_api_t vsf_asn1_reader_api_t;


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_ASN1_READER_API_H_INCLUDED
//  @end
