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
//  Note, elements are written starting from the buffer ending.
//  Note, that all "write" methods move writing position backward.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_asn1_writer.h"
#include "vscf_assert.h"
#include "vscf_asn1_writer_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Reset all internal states and prepare to new ASN.1 writing operations.
//
VSCF_PUBLIC void
vscf_asn1_writer_reset(vscf_impl_t *impl, vsc_buffer_t *out) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->reset_cb);
    asn1_writer_api->reset_cb (impl, out);
}

//
//  Move written data to the buffer beginning and forbid further operations.
//
VSCF_PUBLIC void
vscf_asn1_writer_seal(vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->seal_cb);
    asn1_writer_api->seal_cb (impl);
}

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1_writer_error(vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->error_cb);
    return asn1_writer_api->error_cb (impl);
}

//
//  Move writing position backward for the given length.
//  Return current writing position.
//
VSCF_PUBLIC byte *
vscf_asn1_writer_reserve(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->reserve_cb);
    return asn1_writer_api->reserve_cb (impl, len);
}

//
//  Write ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_tag(vscf_impl_t *impl, int tag) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_tag_cb);
    return asn1_writer_api->write_tag_cb (impl, tag);
}

//
//  Write length of the following data.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_len(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_len_cb);
    return asn1_writer_api->write_len_cb (impl, len);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int(vscf_impl_t *impl, int value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int_cb);
    return asn1_writer_api->write_int_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int32(vscf_impl_t *impl, int32_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int32_cb);
    return asn1_writer_api->write_int32_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int64(vscf_impl_t *impl, int64_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int64_cb);
    return asn1_writer_api->write_int64_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint(vscf_impl_t *impl, unsigned int value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint_cb);
    return asn1_writer_api->write_uint_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint32(vscf_impl_t *impl, uint32_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint32_cb);
    return asn1_writer_api->write_uint32_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint64(vscf_impl_t *impl, uint64_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint64_cb);
    return asn1_writer_api->write_uint64_cb (impl, value);
}

//
//  Write ASN.1 type: BOOLEAN.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_bool(vscf_impl_t *impl, bool value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_bool_cb);
    return asn1_writer_api->write_bool_cb (impl, value);
}

//
//  Write ASN.1 type: NULL.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_null(vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_null_cb);
    return asn1_writer_api->write_null_cb (impl);
}

//
//  Write ASN.1 type: OCTET STRING.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_octet_str(vscf_impl_t *impl, vsc_data_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_octet_str_cb);
    return asn1_writer_api->write_octet_str_cb (impl, value);
}

//
//  Write ASN.1 type: UTF8String.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_utf8_str(vscf_impl_t *impl, vsc_data_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_utf8_str_cb);
    return asn1_writer_api->write_utf8_str_cb (impl, value);
}

//
//  Write ASN.1 type: OID.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_oid(vscf_impl_t *impl, vsc_data_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_oid_cb);
    return asn1_writer_api->write_oid_cb (impl, value);
}

//
//  Mark previously written data of given length as ASN.1 type: SQUENCE.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_sequence(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_sequence_cb);
    return asn1_writer_api->write_sequence_cb (impl, len);
}

//
//  Mark previously written data of given length as ASN.1 type: SET.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_set(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api (impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_set_cb);
    return asn1_writer_api->write_set_cb (impl, len);
}

//
//  Return asn1 writer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_asn1_writer_api_t *
vscf_asn1_writer_api(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api (impl, vscf_api_tag_ASN1_WRITER);
    return (const vscf_asn1_writer_api_t *) api;
}

//
//  Check if given object implements interface 'asn1 writer'.
//
VSCF_PUBLIC bool
vscf_asn1_writer_is_implemented(vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api (impl, vscf_api_tag_ASN1_WRITER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_asn1_writer_api_tag(const vscf_asn1_writer_api_t *asn1_writer_api) {

    VSCF_ASSERT_PTR (asn1_writer_api);

    return asn1_writer_api->api_tag;
}

//
//  Returns implementation unique identifier.
//
VSCF_PUBLIC vscf_impl_tag_t
vscf_asn1_writer_impl_tag(const vscf_asn1_writer_api_t *asn1_writer_api) {

    VSCF_ASSERT_PTR (asn1_writer_api);

    return asn1_writer_api->impl_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
