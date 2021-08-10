//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
#include "vscf_asn1_writer_api.h"
#include "vscf_assert.h"

// clang-format on
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
vscf_asn1_writer_reset(vscf_impl_t *impl, byte *out, size_t out_len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->reset_cb);
    asn1_writer_api->reset_cb (impl, out, out_len);
}

//
//  Finalize writing and forbid further operations.
//
//  Note, that ASN.1 structure is always written to the buffer end, and
//  if argument "do not adjust" is false, then data is moved to the
//  beginning, otherwise - data is left at the buffer end.
//
//  Returns length of the written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_finish(vscf_impl_t *impl, bool do_not_adjust) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->finish_cb);
    return asn1_writer_api->finish_cb (impl, do_not_adjust);
}

//
//  Returns pointer to the inner buffer.
//
VSCF_PUBLIC byte *
vscf_asn1_writer_bytes(vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->bytes_cb);
    return asn1_writer_api->bytes_cb (impl);
}

//
//  Returns total inner buffer length.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_len(const vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->len_cb);
    return asn1_writer_api->len_cb (impl);
}

//
//  Returns how many bytes were already written to the ASN.1 structure.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_written_len(const vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->written_len_cb);
    return asn1_writer_api->written_len_cb (impl);
}

//
//  Returns how many bytes are available for writing.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_unwritten_len(const vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->unwritten_len_cb);
    return asn1_writer_api->unwritten_len_cb (impl);
}

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_asn1_writer_has_error(const vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->has_error_cb);
    return asn1_writer_api->has_error_cb (impl);
}

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_asn1_writer_status(const vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->status_cb);
    return asn1_writer_api->status_cb (impl);
}

//
//  Move writing position backward for the given length.
//  Return current writing position.
//
VSCF_PUBLIC byte *
vscf_asn1_writer_reserve(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_tag_cb);
    return asn1_writer_api->write_tag_cb (impl, tag);
}

//
//  Write context-specific ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_context_tag(vscf_impl_t *impl, int tag, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_context_tag_cb);
    return asn1_writer_api->write_context_tag_cb (impl, tag, len);
}

//
//  Write length of the following data.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_len(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int_cb);
    return asn1_writer_api->write_int_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int8(vscf_impl_t *impl, int8_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int8_cb);
    return asn1_writer_api->write_int8_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int16(vscf_impl_t *impl, int16_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_int16_cb);
    return asn1_writer_api->write_int16_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_int32(vscf_impl_t *impl, int32_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint_cb);
    return asn1_writer_api->write_uint_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint8(vscf_impl_t *impl, uint8_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint8_cb);
    return asn1_writer_api->write_uint8_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint16(vscf_impl_t *impl, uint16_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_uint16_cb);
    return asn1_writer_api->write_uint16_cb (impl, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_uint32(vscf_impl_t *impl, uint32_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_bool_cb);
    return asn1_writer_api->write_bool_cb (impl, value);
}

//
//  Write ASN.1 type: NULL.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_null(vscf_impl_t *impl) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_octet_str_cb);
    return asn1_writer_api->write_octet_str_cb (impl, value);
}

//
//  Write ASN.1 type: BIT STRING with all zero unused bits.
//
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_octet_str_as_bitstring(vscf_impl_t *impl, vsc_data_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_octet_str_as_bitstring_cb);
    return asn1_writer_api->write_octet_str_as_bitstring_cb (impl, value);
}

//
//  Write raw data directly to the ASN.1 structure.
//  Return count of written bytes.
//  Note, use this method carefully.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_data(vscf_impl_t *impl, vsc_data_t data) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_data_cb);
    return asn1_writer_api->write_data_cb (impl, data);
}

//
//  Write ASN.1 type: UTF8String.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_utf8_str(vscf_impl_t *impl, vsc_data_t value) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_oid_cb);
    return asn1_writer_api->write_oid_cb (impl, value);
}

//
//  Mark previously written data of given length as ASN.1 type: SEQUENCE.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1_writer_write_sequence(vscf_impl_t *impl, size_t len) {

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
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

    const vscf_asn1_writer_api_t *asn1_writer_api = vscf_asn1_writer_api(impl);
    VSCF_ASSERT_PTR (asn1_writer_api);

    VSCF_ASSERT_PTR (asn1_writer_api->write_set_cb);
    return asn1_writer_api->write_set_cb (impl, len);
}

//
//  Return asn1 writer API, or NULL if it is not implemented.
//
VSCF_PUBLIC const vscf_asn1_writer_api_t *
vscf_asn1_writer_api(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_ASN1_WRITER);
    return (const vscf_asn1_writer_api_t *) api;
}

//
//  Check if given object implements interface 'asn1 writer'.
//
VSCF_PUBLIC bool
vscf_asn1_writer_is_implemented(const vscf_impl_t *impl) {

    VSCF_ASSERT_PTR (impl);

    return vscf_impl_api(impl, vscf_api_tag_ASN1_WRITER) != NULL;
}

//
//  Returns interface unique identifier.
//
VSCF_PUBLIC vscf_api_tag_t
vscf_asn1_writer_api_tag(const vscf_asn1_writer_api_t *asn1_writer_api) {

    VSCF_ASSERT_PTR (asn1_writer_api);

    return asn1_writer_api->api_tag;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
