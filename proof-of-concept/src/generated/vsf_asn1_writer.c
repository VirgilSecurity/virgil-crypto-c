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


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the ASN.1 writer.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_asn1_writer.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Generated functions.
// ==========================================================================

//  Reset all internal states and prepare to new ASN.1 writing operations.
VSF_PUBLIC int
vsf_asn1_writer_reset (vsf_impl_t *impl, size_t capacity) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->reset_cb);
    return asn1_writer->reset_cb (impl, capacity);
}

//  Returns the result ASN.1 structure.
VSF_PUBLIC const byte *
vsf_asn1_writer_finish (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->finish_cb);
    return asn1_writer->finish_cb (impl);
}

//  Write ASN.1 type: INTEGER.
VSF_PUBLIC int
vsf_asn1_writer_write_int (vsf_impl_t *impl, int val) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_int_cb);
    return asn1_writer->write_int_cb (impl, val);
}

//  Write ASN.1 type: BOOLEAN.
VSF_PUBLIC int
vsf_asn1_writer_write_bool (vsf_impl_t *impl, int val) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_bool_cb);
    return asn1_writer->write_bool_cb (impl, val);
}

//  Write ASN.1 type: NULL.
VSF_PUBLIC int
vsf_asn1_writer_write_null (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_null_cb);
    return asn1_writer->write_null_cb (impl);
}

//  Write ASN.1 type: OCTET STRING.
VSF_PUBLIC int
vsf_asn1_writer_write_octet_string (vsf_impl_t *impl, const byte *data) {

    VSF_ASSERT (impl);
    VSF_ASSERT (data);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_octet_string_cb);
    return asn1_writer->write_octet_string_cb (impl, data);
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_writer_write_utf8_string (vsf_impl_t *impl, const byte *data) {

    VSF_ASSERT (impl);
    VSF_ASSERT (data);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_utf8_string_cb);
    return asn1_writer->write_utf8_string_cb (impl, data);
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_writer_write_tag (vsf_impl_t *impl, size_t tag) {

    VSF_ASSERT (impl);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_tag_cb);
    return asn1_writer->write_tag_cb (impl, tag);
}

//  Write preformatted ASN.1 structure.
VSF_PUBLIC int
vsf_asn1_writer_write_data (vsf_impl_t *impl, const byte *data) {

    VSF_ASSERT (impl);
    VSF_ASSERT (data);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_data_cb);
    return asn1_writer->write_data_cb (impl, data);
}

//  Write ASN.1 type: OID.
VSF_PUBLIC int
vsf_asn1_writer_write_oid (vsf_impl_t *impl, const byte *oid) {

    VSF_ASSERT (impl);
    VSF_ASSERT (oid);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_oid_cb);
    return asn1_writer->write_oid_cb (impl, oid);
}

//  Write ASN.1 type: SEQUENCE.
VSF_PUBLIC int
vsf_asn1_writer_write_sequence (vsf_impl_t *impl, const byte *data) {

    VSF_ASSERT (impl);
    VSF_ASSERT (data);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_sequence_cb);
    return asn1_writer->write_sequence_cb (impl, data);
}

//  Write ASN.1 type: SET OF ANY.
VSF_PUBLIC int
vsf_asn1_writer_write_set (vsf_impl_t *impl, const byte *ar, size_t ar_sz) {

    VSF_ASSERT (impl);
    VSF_ASSERT (ar);

    const vsf_asn1_writer_api_t *asn1_writer = vsf_asn1_writer_api (impl);
    VSF_ASSERT (asn1_writer);

    VSF_ASSERT (asn1_writer->write_set_cb);
    return asn1_writer->write_set_cb (impl, ar, ar_sz);
}

//  Return asn1_writer API, or NULL if it is not implemented.
VSF_PUBLIC const vsf_asn1_writer_api_t *
vsf_asn1_writer_api (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return (vsf_asn1_writer_api_t *) vsf_impl_api (impl, vsf_api_tag_ASN1_WRITER);
}

//  Check if given object implements interface 'asn1_writer'.
VSF_PUBLIC bool
vsf_asn1_writer_is_implemented (vsf_impl_t *impl) {

    VSF_ASSERT (impl);

    return vsf_impl_api (impl, vsf_api_tag_ASN1_WRITER) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end
