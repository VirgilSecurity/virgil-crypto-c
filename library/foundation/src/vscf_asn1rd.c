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
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1rd_internal.h"

#include <mbedtls/asn1.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

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
vscf_asn1rd_mbedtls_has_error(vscf_asn1rd_t *self, int code);

//
//  Read raw data of specific tag the from the buffer.
//
static vsc_data_t
vscf_asn1rd_read_tag_data(vscf_asn1rd_t *self, int tag);


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
vscf_asn1rd_init_ctx(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    self->curr = NULL;
    self->end = NULL;
    self->status = vscf_status_ERROR_UNINITIALIZED;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_asn1rd_cleanup_ctx(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    self->curr = NULL;
    self->end = NULL;
    self->status = vscf_status_ERROR_UNINITIALIZED;
}

//
//  If given mbedtls code is equal to zero, then setup correspond error
//  to the context and return true, otherwise return false.
//
static bool
vscf_asn1rd_mbedtls_has_error(vscf_asn1rd_t *self, int code) {

    VSCF_ASSERT_PTR(self);

    if (0 == code) {
        return false;
    }

    switch (code) {
    case MBEDTLS_ERR_ASN1_INVALID_LENGTH:
    case MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
    case MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        self->status = vscf_status_ERROR_BAD_ASN1;
        break;

    case MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        break;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(code);
        self->status = vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR;
        break;
    }

    return true;
}

//
//  Read raw data of specific tag the from the buffer.
//
static vsc_data_t
vscf_asn1rd_read_tag_data(vscf_asn1rd_t *self, int tag) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&self->curr, self->end, &len, tag);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return vsc_data_empty();
    }

    VSCF_ASSERT_OPT(self->curr + len <= self->end);

    self->curr += len;

    return vsc_data(self->curr - len, len);
}

//
//  Reset all internal states and prepare to new ASN.1 reading operations.
//
VSCF_PUBLIC void
vscf_asn1rd_reset(vscf_asn1rd_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(data.bytes);

    self->curr = (byte *)data.bytes;
    self->end = data.bytes + data.len;

    self->status = vscf_status_SUCCESS;
}

//
//  Return length in bytes how many bytes are left for reading.
//
VSCF_PUBLIC size_t
vscf_asn1rd_left_len(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    VSCF_ASSERT_PTR(self->curr <= self->end);
    return (size_t)(self->end - self->curr);
}

//
//  Return true if status is not "success".
//
VSCF_PUBLIC bool
vscf_asn1rd_has_error(const vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->status != vscf_status_SUCCESS;
}

//
//  Return error code.
//
VSCF_PUBLIC vscf_status_t
vscf_asn1rd_status(const vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->status;
}

//
//  Get tag of the current ASN.1 element.
//
VSCF_PUBLIC int
vscf_asn1rd_get_tag(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (self->curr == self->end) {
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        return 0;
    }

    return *self->curr;
}

//
//  Get length of the current ASN.1 element.
//
VSCF_PUBLIC size_t
vscf_asn1rd_get_len(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (self->curr == self->end) {
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        return 0;
    }

    byte *p = self->curr + 1; // skip tag

    size_t len = 0;
    int ret = mbedtls_asn1_get_len(&p, self->end, &len);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return 0;
    }

    return len;
}

//
//  Get length of the current ASN.1 element with tag and length itself.
//
VSCF_PUBLIC size_t
vscf_asn1rd_get_data_len(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (self->curr == self->end) {
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        return 0;
    }

    byte *p = self->curr + 1; // skip tag

    size_t length_len = 1;
    if ((*p & 0x80) > 0) {
        length_len += *p & 0x7F;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_len(&p, self->end, &len);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return 0;
    }

    return 1 + length_len + len;
}

//
//  Read ASN.1 type: TAG.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_tag(vscf_asn1rd_t *self, int tag) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&self->curr, self->end, &len, tag);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return 0;
    }

    return len;
}

//
//  Read ASN.1 type: context-specific TAG.
//  Return element length.
//  Return 0 if current position do not points to the requested tag.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_context_tag(vscf_asn1rd_t *self, int tag) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (self->curr == self->end) {
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        return 0;
    }

    int expected_tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
    int read_tag = vscf_asn1rd_get_tag(self);
    if (expected_tag == read_tag) {
        return vscf_asn1rd_read_tag(self, expected_tag);
    }

    return 0;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int
vscf_asn1rd_read_int(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    int64_t value = vscf_asn1rd_read_int64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int8_t
vscf_asn1rd_read_int8(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    int64_t value = vscf_asn1rd_read_int64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value < (int64_t)INT8_MIN || value > (int64_t)INT8_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int8_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int16_t
vscf_asn1rd_read_int16(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    int64_t value = vscf_asn1rd_read_int64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (int64_t)INT16_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int16_t)(0xFFFFFFFF & value);
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int32_t
vscf_asn1rd_read_int32(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    int64_t value = vscf_asn1rd_read_int64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value < (int64_t)INT32_MIN || value > (int64_t)INT32_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (int32_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC int64_t
vscf_asn1rd_read_int64(vscf_asn1rd_t *self) {

    //  Initial implementation is taken from MbedTLS library.

    VSCF_ASSERT_PTR(self);

    size_t len = vscf_asn1rd_read_tag(self, MBEDTLS_ASN1_INTEGER);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (len == 0) {
        self->status = vscf_status_ERROR_BAD_ASN1;
        return 0;
    }

    if (len > sizeof(int64_t)) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    int64_t value = (*self->curr & 0x80) ? -1 : 0;
    while (len-- > 0) {
        value = (value << 8) | *self->curr;
        ++self->curr;
    }

    return value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC unsigned int
vscf_asn1rd_read_uint(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    uint64_t value = vscf_asn1rd_read_uint64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (unsigned int)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint8_t
vscf_asn1rd_read_uint8(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    uint64_t value = vscf_asn1rd_read_uint64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT8_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint8_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint16_t
vscf_asn1rd_read_uint16(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    uint64_t value = vscf_asn1rd_read_uint64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT16_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint16_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint32_t
vscf_asn1rd_read_uint32(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    uint64_t value = vscf_asn1rd_read_uint64(self);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (value > (uint64_t)UINT32_MAX) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    return (uint32_t)value;
}

//
//  Read ASN.1 type: INTEGER.
//
VSCF_PUBLIC uint64_t
vscf_asn1rd_read_uint64(vscf_asn1rd_t *self) {

    //  Initial implementation is taken from MbedTLS library.

    VSCF_ASSERT_PTR(self);

    size_t len = vscf_asn1rd_read_tag(self, MBEDTLS_ASN1_INTEGER);


    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    if (len == 0) {
        self->status = vscf_status_ERROR_BAD_ASN1;
        return 0;
    }

    if (len > sizeof(uint64_t) + 1) {
        self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
        return 0;
    }

    if (len == sizeof(uint64_t) + 1) {
        if (*self->curr == 0x00) {
            ++self->curr;
            --len;
        } else {
            self->status = vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING;
            return 0;
        }
    }

    uint64_t value = 0;

    while (len-- > 0) {
        value = (value << 8) | *self->curr;
        ++self->curr;
    }

    return value;
}

//
//  Read ASN.1 type: BOOLEAN.
//
VSCF_PUBLIC bool
vscf_asn1rd_read_bool(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return 0;
    }

    int value = 0;
    int ret = mbedtls_asn1_get_bool(&self->curr, self->end, &value);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return 0;
    }

    return value;
}

//
//  Read ASN.1 type: NULL.
//
VSCF_PUBLIC void
vscf_asn1rd_read_null(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return;
    }

    size_t len = 0;
    int ret = mbedtls_asn1_get_tag(&self->curr, self->end, &len, MBEDTLS_ASN1_NULL);

    if (vscf_asn1rd_mbedtls_has_error(self, ret)) {
        return;
    }

    VSCF_ASSERT(0 == len && "length of the NULL must be 0");
}

//
//  Read ASN.1 type: NULL, only if it exists.
//  Note, this method is safe to call even no more data is left for reading.
//
VSCF_PUBLIC void
vscf_asn1rd_read_null_optional(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return;
    }

    if (vscf_asn1rd_left_len(self) == 0) {
        return;
    }

    if (vscf_asn1rd_get_tag(self) == vscf_asn1_tag_NULL) {
        vscf_asn1rd_read_null(self);
    }
}

//
//  Read ASN.1 type: OCTET STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_octet_str(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    return vscf_asn1rd_read_tag_data(self, MBEDTLS_ASN1_OCTET_STRING);
}

//
//  Read ASN.1 type: BIT STRING.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_bitstring_as_octet_str(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    vsc_data_t value = vscf_asn1rd_read_tag_data(self, MBEDTLS_ASN1_BIT_STRING);

    if ((value.len > 0) && (*value.bytes == 0x00)) {
        return vsc_data_slice_beg(value, 1, value.len - 1);
    }

    return value;
}

//
//  Read ASN.1 type: UTF8String.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_utf8_str(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    return vscf_asn1rd_read_tag_data(self, MBEDTLS_ASN1_UTF8_STRING);
}

//
//  Read ASN.1 type: OID.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_oid(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    VSCF_ASSERT(self->status != vscf_status_ERROR_UNINITIALIZED);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    return vscf_asn1rd_read_tag_data(self, MBEDTLS_ASN1_OID);
}

//
//  Read raw data of given length.
//
VSCF_PUBLIC vsc_data_t
vscf_asn1rd_read_data(vscf_asn1rd_t *self, size_t len) {

    VSCF_ASSERT_PTR(self);

    if (self->status != vscf_status_SUCCESS) {
        return vsc_data_empty();
    }

    if (self->curr + len > self->end) {
        self->status = vscf_status_ERROR_OUT_OF_DATA;
        return vsc_data_empty();
    }

    self->curr += len;

    return vsc_data(self->curr - len, len);
}

//
//  Read ASN.1 type: SEQUENCE.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_sequence(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_asn1rd_read_tag(self, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
}

//
//  Read ASN.1 type: SET.
//  Return element length.
//
VSCF_PUBLIC size_t
vscf_asn1rd_read_set(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_asn1rd_read_tag(self, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
}
