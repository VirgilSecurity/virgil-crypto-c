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
//  This module contains 'asn1wr' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_asn1wr.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1.h"
#include "vscf_asn1wr_impl.h"
#include "vscf_asn1wr_internal.h"

#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <virgil/common/private/vsc_buffer_defs.h>
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
vscf_asn1wr_mbedtls_has_error(vscf_asn1wr_impl_t *asn1wr_impl, int code);

//
//  Write raw data of specific tag the to the buffer.
//
static size_t
vscf_asn1wr_write_raw_data(vscf_asn1wr_impl_t *asn1wr_impl, const vsc_data_t data, int tag);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//
VSCF_PRIVATE vscf_error_t
vscf_asn1wr_init_ctx(vscf_asn1wr_impl_t *asn1wr_impl) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    vscf_zeroize(asn1wr_impl, sizeof(vscf_asn1wr_impl_t));

    asn1wr_impl->error = vscf_error_UNINITIALIZED;

    return vscf_SUCCESS;
}

//
//  Provides cleanup of the implementation specific context.
//
VSCF_PRIVATE void
vscf_asn1wr_cleanup_ctx(vscf_asn1wr_impl_t *asn1wr_impl) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    vscf_zeroize(asn1wr_impl, sizeof(vscf_asn1wr_impl_t));
}

//
//  If given mbedtls code is equal to zero, then setup correspond error
//  to the context and return true, otherwise return false.
//
static bool
vscf_asn1wr_mbedtls_has_error(vscf_asn1wr_impl_t *asn1wr_impl, int code) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (code >= 0) {
        return false;
    }

    switch (code) {
    case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
        asn1wr_impl->error = vscf_error_SMALL_BUFFER;
        break;

    default:
        VSCF_ASSERT(0 && "unhandled mbedtls error");
        asn1wr_impl->error = vscf_error_UNHANDLED_THIRDPARTY_ERROR;
    }

    return true;
}

//
//  Write raw data of specific tag the to the buffer.
//
static size_t
vscf_asn1wr_write_raw_data(vscf_asn1wr_impl_t *asn1wr_impl, const vsc_data_t data, int tag) {

    VSCF_ASSERT_PTR(asn1wr_impl);
    VSCF_ASSERT_PTR(data.bytes);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_raw_buffer(&asn1wr_impl->curr, asn1wr_impl->start, data.bytes, data.len);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    size_t size = 0;

    size += vscf_asn1wr_write_len(asn1wr_impl, data.len);
    size += vscf_asn1wr_write_tag(asn1wr_impl, tag);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    return (size_t)ret + size;
}

//
//  Reset all internal states and prepare to new ASN.1 writing operations.
//
VSCF_PUBLIC void
vscf_asn1wr_reset(vscf_asn1wr_impl_t *asn1wr_impl, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(asn1wr_impl);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(out->bytes);
    VSCF_ASSERT(out->capacity > 0);
    VSCF_ASSERT(out->len < out->capacity);

    asn1wr_impl->out = out;
    asn1wr_impl->start = out->bytes + out->len;
    asn1wr_impl->curr = out->bytes + out->capacity;
    asn1wr_impl->error = vscf_SUCCESS;
}

//
//  Move written data to the buffer beginning and forbid further operations.
//
VSCF_PUBLIC void
vscf_asn1wr_seal(vscf_asn1wr_impl_t *asn1wr_impl) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    VSCF_ASSERT(asn1wr_impl->error == vscf_SUCCESS);

    size_t size = (size_t)(asn1wr_impl->out->bytes + asn1wr_impl->out->capacity - asn1wr_impl->curr);

    asn1wr_impl->out->len += size;

    VSCF_ASSERT(asn1wr_impl->out->len <= asn1wr_impl->out->capacity);

    if (asn1wr_impl->start < asn1wr_impl->curr) {

        memmove(asn1wr_impl->start, asn1wr_impl->curr, size);
    }

    vscf_asn1wr_init_ctx(asn1wr_impl);
}

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1wr_error(vscf_asn1wr_impl_t *asn1wr_impl) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    return asn1wr_impl->error;
}

//
//  Move writing position backward for the given length.
//  Return current writing position.
//
VSCF_PUBLIC byte *
vscf_asn1wr_reserve(vscf_asn1wr_impl_t *asn1wr_impl, size_t len) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (asn1wr_impl->start > asn1wr_impl->curr - len) {
        asn1wr_impl->error = vscf_error_SMALL_BUFFER;
        return NULL;
    }

    asn1wr_impl->curr -= len;
    return asn1wr_impl->curr;
}

//
//  Write ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_tag(vscf_asn1wr_impl_t *asn1wr_impl, int tag) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    VSCF_ASSERT(tag > 0);
    VSCF_ASSERT(tag <= 0xFF);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_tag(&asn1wr_impl->curr, asn1wr_impl->start, (unsigned char)tag);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write length of the following data.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_len(vscf_asn1wr_impl_t *asn1wr_impl, size_t len) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_len(&asn1wr_impl->curr, asn1wr_impl->start, len);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int(vscf_asn1wr_impl_t *asn1wr_impl, int value) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_int(&asn1wr_impl->curr, asn1wr_impl->start, value);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: BOOLEAN.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_bool(vscf_asn1wr_impl_t *asn1wr_impl, bool value) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_bool(&asn1wr_impl->curr, asn1wr_impl->start, value);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: NULL.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_null(vscf_asn1wr_impl_t *asn1wr_impl) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    if (asn1wr_impl->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_null(&asn1wr_impl->curr, asn1wr_impl->start);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr_impl, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: OCTET STRING.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_octet_str(vscf_asn1wr_impl_t *asn1wr_impl, const vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr_impl);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_raw_data(asn1wr_impl, value, MBEDTLS_ASN1_OCTET_STRING);
}

//
//  Write ASN.1 type: UTF8String.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_utf8_str(vscf_asn1wr_impl_t *asn1wr_impl, const vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr_impl);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_raw_data(asn1wr_impl, value, MBEDTLS_ASN1_UTF8_STRING);
}

//
//  Write ASN.1 type: OID.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_oid(vscf_asn1wr_impl_t *asn1wr_impl, const vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr_impl);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_raw_data(asn1wr_impl, value, MBEDTLS_ASN1_OID);
}

//
//  Mark previously written data of given length as ASN.1 type: SQUENCE.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_sequence(vscf_asn1wr_impl_t *asn1wr_impl, size_t len) {

    VSCF_ASSERT_PTR(asn1wr_impl);

    size_t result_len = 0;

    result_len += vscf_asn1wr_write_len(asn1wr_impl, len);
    result_len += vscf_asn1wr_write_tag(asn1wr_impl, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    return result_len;
}

//
//  Mark previously written data of given length as ASN.1 type: SET.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_set(vscf_asn1wr_impl_t *asn1wr_impl, size_t len) {

    size_t result_len = 0;

    result_len += vscf_asn1wr_write_len(asn1wr_impl, len);
    result_len += vscf_asn1wr_write_tag(asn1wr_impl, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

    return result_len;
}
