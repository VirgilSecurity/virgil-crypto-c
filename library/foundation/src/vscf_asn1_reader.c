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


//  @description
// --------------------------------------------------------------------------
//  Provides interface to the ASN.1 reader.
//  Note, that all "read" methods move reading position forward.
//  Note, that all "get" do not change reading position.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_asn1_reader.h"
#include "vscf_assert.h"
#include "vscf_asn1_reader_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Reset all internal states and prepare to new ASN.1 reading operations.
//
VSCF_PUBLIC void
vscf_asn1_reader_reset(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->reset_cb);
    asn1_reader_api->reset_cb (impl, data);
}

//
//  Return length in bytes how many bytes are left for reading.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_left_len(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->left_len_cb);
    return asn1_reader_api->left_len_cb (impl);
}

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_asn1_reader_has_error(const vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->has_error_cb);
    return asn1_reader_api->has_error_cb (impl);
}

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_asn1_reader_status(const vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->status_cb);
    return asn1_reader_api->status_cb (impl);
}

//
//  Get tag of the current ASN.1 element.
//
VSCF_PUBLIC int
vscf_asn1_reader_get_tag(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->get_tag_cb);
    return asn1_reader_api->get_tag_cb (impl);
}

//
//  Get length of the current ASN.1 element.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_get_len(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->get_len_cb);
    return asn1_reader_api->get_len_cb (impl);
}

//
//  Get length of the current ASN.1 element with tag and length itself.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_get_data_len(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->get_data_len_cb);
    return asn1_reader_api->get_data_len_cb (impl);
}

//
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_tag(vscf_impl_t *impl, int tag) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_tag_cb);
    return asn1_reader_api->read_tag_cb (impl, tag);
}

//
//  Read ASN.1 type: context-specific TAG.
//  Return element length.
//  Return 0 if current position do not points to the requested tag.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_context_tag(vscf_impl_t *impl, int tag) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_context_tag_cb);
    return asn1_reader_api->read_context_tag_cb (impl, tag);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1_reader_read_int(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_int_cb);
    return asn1_reader_api->read_int_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int8_t
vscf_asn1_reader_read_int8(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_int8_cb);
    return asn1_reader_api->read_int8_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int16_t
vscf_asn1_reader_read_int16(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_int16_cb);
    return asn1_reader_api->read_int16_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int32_t
vscf_asn1_reader_read_int32(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_int32_cb);
    return asn1_reader_api->read_int32_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int64_t
vscf_asn1_reader_read_int64(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_int64_cb);
    return asn1_reader_api->read_int64_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC unsigned int
vscf_asn1_reader_read_uint(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_uint_cb);
    return asn1_reader_api->read_uint_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint8_t
vscf_asn1_reader_read_uint8(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_uint8_cb);
    return asn1_reader_api->read_uint8_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint16_t
vscf_asn1_reader_read_uint16(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_uint16_cb);
    return asn1_reader_api->read_uint16_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint32_t
vscf_asn1_reader_read_uint32(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_uint32_cb);
    return asn1_reader_api->read_uint32_cb (impl);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint64_t
vscf_asn1_reader_read_uint64(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_uint64_cb);
    return asn1_reader_api->read_uint64_cb (impl);
}

//
//  Read ASN.1 type: BOOLEAN.
//
VSCF_PUBLIC bool
vscf_asn1_reader_read_bool(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_bool_cb);
    return asn1_reader_api->read_bool_cb (impl);
}

//
//  Read ASN.1 type: NULL.
//
VSCF_PUBLIC void
vscf_asn1_reader_read_null(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_null_cb);
    asn1_reader_api->read_null_cb (impl);
}

//
//  Read ASN.1 type: NULL, only if it exists.
//  Note, this method is safe to call even no more data is left for reading.
//
VSCF_PUBLIC void
vscf_asn1_reader_read_null_optional(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_null_optional_cb);
    asn1_reader_api->read_null_optional_cb (impl);
}

//
//  Read ASN.1 type: OCTET STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_octet_str(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_octet_str_cb);
    return asn1_reader_api->read_octet_str_cb (impl);
}

//
//  Read ASN.1 type: BIT STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_bitstring_as_octet_str(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_bitstring_as_octet_str_cb);
    return asn1_reader_api->read_bitstring_as_octet_str_cb (impl);
}

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_utf8_str(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_utf8_str_cb);
    return asn1_reader_api->read_utf8_str_cb (impl);
}

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_oid(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_oid_cb);
    return asn1_reader_api->read_oid_cb (impl);
}

//
//  Read raw data of given length.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1_reader_read_data(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_data_cb);
    return asn1_reader_api->read_data_cb (impl, len);
}

//
//  Read ASN.1 type: SEQUENCE.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_sequence(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_sequence_cb);
    return asn1_reader_api->read_sequence_cb (impl);
}

//
//  Read ASN.1 type: SET.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1_reader_read_set(vscf_impl_t *impl) {

    const vscf_asn1_reader_api_t *asn1_reader_api = vscf_asn1_reader_api(impl);
    VSCF_ASSERT_PTR (asn1_reader_api);

    VSCF_ASSERT_PTR (asn1_reader_api->read_set_cb);
    return asn1_reader_api->read_set_cb (impl);
}

//
//  Return asn1 reader API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_asn1_reader_api_t *
vscf_asn1_reader_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_ASN1_READER);
    return (const vscf_asn1_reader_api_t *) api;
}

//
//  Check if given object implements interface 'asn1 reader'.
//
VSCF_PUBLIC bool
vscf_asn1_reader_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_ASN1_READER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_asn1_reader_api_tag(const vscf_asn1_reader_api_t *asn1_reader_api) {

    VSCF_ASSERT_PTR (asn1_reader_api);

    return asn1_reader_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
