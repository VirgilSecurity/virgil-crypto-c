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


//  @description
// --------------------------------------------------------------------------
//  This module contains 'asn1rd' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_asn1rd.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1rd_impl.h"
#include "vscf_asn1rd_internal.h"

#include <mbedtls/asn1.h>
#include <vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  If given mbedtls code is equal to zero, then setup correspond error
//  to the context and return true, otherwise return false.
//
static bool
vscf_asn1rd_mbedtls_has_error(vscf_asn1rd_impl_t *asn1rd_impl, int code);

//
//  Read raw data of specific tag the from the buffer.
//
static void
vscf_asn1rd_read_tag_data(vscf_asn1rd_impl_t *asn1rd_impl, int tag, vsc_buffer_t *buffer);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_asn1rd_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_asn1rd_init_ctx(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    asn1rd_impl->curr = NULL;
    asn1rd_impl->end = NULL;
    asn1rd_impl->error = vscf_error_UNINITIALIZED;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_asn1rd_cleanup_ctx(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    asn1rd_impl->curr = NULL;
    asn1rd_impl->end = NULL;
    asn1rd_impl->error = vscf_error_UNINITIALIZED;
}

//
//  If given mbedtls code is equal to zero, then setup correspond error
//  to the context and return true, otherwise return false.
//
static bool
vscf_asn1rd_mbedtls_has_error(vscf_asn1rd_impl_t *asn1rd_impl, int code) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    if (0 == code) {
        return false;
    }

    switch (code) {
    case MBEDTLS_ERR_ASN1_INVALID_LENGTH:
    case MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
    case MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        asn1rd_impl->error = vscf_error_BAD_ASN1;
        break;

    case MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        asn1rd_impl->error = vscf_error_OUT_OF_DATA;
        break;

    default:
        VSCF_ASSERT(0 && "unhandled mbedtls error");
        asn1rd_impl->error = vscf_error_UNHANDLED_THIRDPARTY_ERROR;
        break;
    }

    return true;
}

//
//  Read raw data of specific tag the from the buffer.
//
static void
vscf_asn1rd_read_tag_data(vscf_asn1rd_impl_t *asn1rd_impl, int tag, vsc_buffer_t *buffer) {

    VSCF_ASSERT_PTR(asn1rd_impl);
    VSCF_ASSERT_PTR(buffer);
    VSCF_ASSERT_PTR(buffer->bytes);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&asn1rd_impl->curr, asn1rd_impl->end, &len, tag);

    if (vscf_asn1rd_mbedtls_has_error(asn1rd_impl, ret)) {
        return;
    }

    VSCF_ASSERT_OPT(asn1rd_impl->curr + len <= asn1rd_impl->end);

    if (len > buffer->capacity) {
        asn1rd_impl->error = vscf_error_SMALL_BUFFER;
        return;
    }

    memcpy(buffer->bytes, asn1rd_impl->curr, len);
    buffer->len = len;
    asn1rd_impl->curr += len;
}

//
//  Reset all internal states and prepare to new ASN.1 reading operations.
//
VSCF_PUBLIC void
vscf_asn1rd_reset(vscf_asn1rd_impl_t *asn1rd_impl, vsc_data_t data) {

    VSCF_ASSERT_PTR(asn1rd_impl);
    VSCF_ASSERT_PTR(data.bytes);

    asn1rd_impl->curr = (byte *)data.bytes;
    asn1rd_impl->end = data.bytes + data.len;

    asn1rd_impl->error = vscf_SUCCESS;
}

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1rd_error(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    return asn1rd_impl->error;
}

//
//  Get tag of the current ASN.1 element.
//
VSCF_PUBLIC int
vscf_asn1rd_get_tag(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    return *asn1rd_impl->curr;
}

//
//  Get length of the current ASN.1 element.
//
VSCF_PUBLIC size_t
vscf_asn1rd_get_len(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (asn1rd_impl->curr == asn1rd_impl->end) {
        asn1rd_impl->error = vscf_error_OUT_OF_DATA;
        return 0;
    }

    byte *p = asn1rd_impl->curr + 1; // skip tag

    size_t len = 0;
    int ret = mbedtls_asn1_get_len(&p, asn1rd_impl->end, &len);

    if (vscf_asn1rd_mbedtls_has_error(asn1rd_impl, ret)) {
        return 0;
    }

    return len;
}

//
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_tag(vscf_asn1rd_impl_t *asn1rd_impl, int tag) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&asn1rd_impl->curr, asn1rd_impl->end, &len, tag);

    if (vscf_asn1rd_mbedtls_has_error(asn1rd_impl, ret)) {
        return 0;
    }

    return len;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1rd_read_int(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    int64_t value = vscf_asn1rd_read_int64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int8_t
vscf_asn1rd_read_int8(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    int64_t value = vscf_asn1rd_read_int64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT8_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int8_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int16_t
vscf_asn1rd_read_int16(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    int64_t value = vscf_asn1rd_read_int64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT16_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int16_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int32_t
vscf_asn1rd_read_int32(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    int64_t value = vscf_asn1rd_read_int64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT32_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int32_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int64_t
vscf_asn1rd_read_int64(vscf_asn1rd_impl_t *asn1rd_impl) {

    //  Initial implementation is taken from MbedTLS library.

    VSCF_ASSERT_PTR(asn1rd_impl);

    size_t len = vscf_asn1rd_read_tag(asn1rd_impl, MBEDTLS_ASN1_INTEGER);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (len == 0 || len > sizeof(int64_t) || (*asn1rd_impl->curr & 0x80) != 0) {
        asn1rd_impl->error = vscf_error_BAD_ASN1;
        return 0;
    }

    int64_t value = 0;

    while (len-- > 0) {
        value = (value << 8) | (int64_t)(*asn1rd_impl->curr);
        ++asn1rd_impl->curr;
    }

    return value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC unsigned int
vscf_asn1rd_read_uint(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    uint64_t value = vscf_asn1rd_read_uint64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (unsigned int)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint8_t
vscf_asn1rd_read_uint8(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    uint64_t value = vscf_asn1rd_read_uint64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT8_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint8_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint16_t
vscf_asn1rd_read_uint16(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    uint64_t value = vscf_asn1rd_read_uint64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT16_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint16_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint32_t
vscf_asn1rd_read_uint32(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    uint64_t value = vscf_asn1rd_read_uint64(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT32_MAX) {
        asn1rd_impl->error = vscf_error_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint32_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint64_t
vscf_asn1rd_read_uint64(vscf_asn1rd_impl_t *asn1rd_impl) {

    //  Initial implementation is taken from MbedTLS library.

    VSCF_ASSERT_PTR(asn1rd_impl);

    size_t len = vscf_asn1rd_read_tag(asn1rd_impl, MBEDTLS_ASN1_INTEGER);


    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    if (len == 0 || len > sizeof(int64_t) || (*asn1rd_impl->curr & 0x80) != 0) {
        asn1rd_impl->error = vscf_error_BAD_ASN1;
        return 0;
    }

    uint64_t value = 0;

    while (len-- > 0) {
        value = (value << 8) | *asn1rd_impl->curr;
        ++asn1rd_impl->curr;
    }

    return value;
}

//
//  Read ASN.1 type: BOOLEAN.
//
VSCF_PUBLIC bool
vscf_asn1rd_read_bool(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int value = 0;
    int ret = mbedtls_asn1_get_bool(&asn1rd_impl->curr, asn1rd_impl->end, &value);

    if (vscf_asn1rd_mbedtls_has_error(asn1rd_impl, ret)) {
        return 0;
    }

    return value;
}

//
//  Read ASN.1 type: NULL.
//
VSCF_PUBLIC void
vscf_asn1rd_read_null(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&asn1rd_impl->curr, asn1rd_impl->end, &len, MBEDTLS_ASN1_NULL);

    if (vscf_asn1rd_mbedtls_has_error(asn1rd_impl, ret)) {
        return;
    }

    VSCF_ASSERT(0 == len && "length of the NULL must be 0");
}

//
//  Read ASN.1 type: OCTET STRING.
//
VSCF_PUBLIC void
vscf_asn1rd_read_octet_str(vscf_asn1rd_impl_t *asn1rd_impl, vsc_buffer_t *value) {

    VSCF_ASSERT_PTR(asn1rd_impl);
    VSCF_ASSERT_PTR(value);
    VSCF_ASSERT_PTR(value->bytes);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return;
    }

    vscf_asn1rd_read_tag_data(asn1rd_impl, MBEDTLS_ASN1_OCTET_STRING, value);
}

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC void
vscf_asn1rd_read_utf8_str(vscf_asn1rd_impl_t *asn1rd_impl, vsc_buffer_t *value) {

    VSCF_ASSERT_PTR(asn1rd_impl);
    VSCF_ASSERT_PTR(value);
    VSCF_ASSERT_PTR(value->bytes);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return;
    }

    vscf_asn1rd_read_tag_data(asn1rd_impl, MBEDTLS_ASN1_UTF8_STRING, value);
}

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC void
vscf_asn1rd_read_oid(vscf_asn1rd_impl_t *asn1rd_impl, vsc_buffer_t *value) {

    VSCF_ASSERT_PTR(asn1rd_impl);
    VSCF_ASSERT_PTR(value);
    VSCF_ASSERT_PTR(value->bytes);

    VSCF_ASSERT(asn1rd_impl->error != vscf_error_UNINITIALIZED);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return;
    }

    vscf_asn1rd_read_tag_data(asn1rd_impl, MBEDTLS_ASN1_OID, value);
}

//
//  Read raw data of given length.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_data(vscf_asn1rd_impl_t *asn1rd_impl, size_t len) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    if (asn1rd_impl->error != vscf_SUCCESS) {
        return vsc_data_empty();
    }

    if (asn1rd_impl->curr + len > asn1rd_impl->end) {
        asn1rd_impl->error = vscf_error_OUT_OF_DATA;
        return vsc_data_empty();
    }

    asn1rd_impl->curr += len;

    return vsc_data(asn1rd_impl->curr - len, len);
}

//
//  Read ASN.1 type: CONSTRUCTED | SEQUENCE.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_sequence(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    return vscf_asn1rd_read_tag(asn1rd_impl, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
}

//
//  Read ASN.1 type: CONSTRUCTED | SET.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_set(vscf_asn1rd_impl_t *asn1rd_impl) {

    VSCF_ASSERT_PTR(asn1rd_impl);

    return vscf_asn1rd_read_tag(asn1rd_impl, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
}
