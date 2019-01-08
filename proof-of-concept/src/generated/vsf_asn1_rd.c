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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'vsf_asn1_rd_t' object management.
//  It includes:
//      - lifecycle functions;
//      - dependency management functions;
//      - RTTI functions.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_asn1_rd.h"
#include "vsf_asn1_rd_private.h"
#include "vsf_asn1_rd_asn1_reader.h"
#include "vsf_impl_private.h"
//  @end


#include "vsf_asn1_reader_api.h"


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Objects.
// ==========================================================================

//  Interface 'asn1_reader' API.
static vsf_asn1_reader_api_t asn1_reader_api = {
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_reader' MUST be equal to the 'vsf_api_tag_ASN1_READER'.
    vsf_api_tag_ASN1_READER,

    //  Reset all internal states and prepare to new ASN.1 reading operations.
    (vsf_asn1_reader_api_reset_fn) vsf_asn1_rd_asn1_reader_reset,

    //  Read ASN.1 type: INTEGER.
    (vsf_asn1_reader_api_read_int_fn) vsf_asn1_rd_asn1_reader_read_int,

    //  Read ASN.1 type: BOOLEAN.
    (vsf_asn1_reader_api_read_bool_fn) vsf_asn1_rd_asn1_reader_read_bool,

    //  Read ASN.1 type: NULL.
    (vsf_asn1_reader_api_read_null_fn) vsf_asn1_rd_asn1_reader_read_null,

    //  Read ASN.1 type: OCTET STRING.
    (vsf_asn1_reader_api_read_octet_str_fn) vsf_asn1_rd_asn1_reader_read_octet_str,

    //  Read ASN.1 type: UTF8String.
    (vsf_asn1_reader_api_read_utf8_str_fn) vsf_asn1_rd_asn1_reader_read_utf8_str,

    //  Read preformatted ASN.1 structure.
    (vsf_asn1_reader_api_read_fn) vsf_asn1_rd_asn1_reader_read,

    //  Read ASN.1 type: TAG.
    (vsf_asn1_reader_api_read_tag_fn) vsf_asn1_rd_asn1_reader_read_tag,

    //  Read ASN.1 type: OID.
    (vsf_asn1_reader_api_read_oid_fn) vsf_asn1_rd_asn1_reader_read_oid,

    //  Read ASN.1 type: SEQUENCE.
    (vsf_asn1_reader_api_read_sequence_fn) vsf_asn1_rd_asn1_reader_read_sequence,

    //  Read ASN.1 type: SET.
    (vsf_asn1_reader_api_read_set_fn) vsf_asn1_rd_asn1_reader_read_set,
};

//  NULL terminated array of the implemented interfaces.
//  MUST be second in the structure.
static const void * const api_array[] = {
    &asn1_reader_api,
    NULL,
};

//  Compile-time known information about 'asn1_rd' implementation.
static vsf_impl_info_t impl_info = {
    //  Implementation unique identifier, MUST be first in the structure.
    vsf_impl_tag_ASN1_RD,

    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    api_array,

    //  Erase inner state in a secure manner.
    vsf_asn1_rd_cleanup,

    //  Self destruction, according to destruction policy.
    vsf_asn1_rd_destroy,
};


// ==========================================================================
//  Types.
// ==========================================================================

//  This type contains implementation details.
struct vsf_asn1_rd_t {
    //  Compile-time known information about this implementation.
    const vsf_impl_info_t *info;

    //  Interface implementation specific context.
    vsf_asn1_rd_context_t context;
};
typedef struct vsf_asn1_rd_t vsf_asn1_rd_t;


// ==========================================================================
//  Generated functions.
// ==========================================================================

VSF_PUBLIC void
vsf_asn1_rd_cleanup (void) {

    //TODO: Implement me.
}

VSF_PUBLIC void
vsf_asn1_rd_destroy (void) {

    //TODO: Implement me.
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
