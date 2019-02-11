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
#include "vscf_asn1_tag.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_asn1wr_internal.h"

#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

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
vscf_asn1wr_mbedtls_has_error(vscf_asn1wr_t *asn1wr, int code);

//
//  Write raw data and with given tag the to ASN.1 structure.
//
static size_t
vscf_asn1wr_write_tag_data(vscf_asn1wr_t *asn1wr, vsc_data_t data, int tag);

//
//  Get length of the current ASN.1 element with tag and length itself.
//
static size_t
vscf_asn1wr_get_current_element_len(byte *curr, const byte *end);

//
//  Swap positions of the given ASN.1 elements.
//  Note, "from" element must be behind "to" element.
//  Note, algorithm complexity is O^2.
//
static void
vscf_asn1wr_swap_elements_of_set(byte *to_start, size_t to_len, byte *from_start, size_t from_len);

//
//  Return true if second element is lexicographical less then first.
//
static bool
vscf_asn1wr_second_element_of_set_is_less(const byte *first_start, size_t first_len, const byte *second_start,
        size_t second_len);

//
//  Perform lexicographical sorting of the given elements of set.
//
static void
vscf_asn1wr_sort_elements_of_set(vscf_asn1wr_t *asn1wr, size_t len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_asn1wr_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_asn1wr_init_ctx(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);

    asn1wr->start = NULL;
    asn1wr->curr = NULL;
    asn1wr->error = vscf_error_UNINITIALIZED;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_asn1wr_cleanup_ctx(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);

    asn1wr->start = NULL;
    asn1wr->curr = NULL;
    asn1wr->error = vscf_error_UNINITIALIZED;
}

//
//  If given mbedtls code is equal to zero, then setup correspond error
//  to the context and return true, otherwise return false.
//
static bool
vscf_asn1wr_mbedtls_has_error(vscf_asn1wr_t *asn1wr, int code) {

    VSCF_ASSERT_PTR(asn1wr);

    if (code >= 0) {
        return false;
    }

    switch (code) {
    case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
        asn1wr->error = vscf_error_SMALL_BUFFER;
        break;

    default:
        VSCF_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(code);
        asn1wr->error = vscf_error_UNHANDLED_THIRDPARTY_ERROR;
        break;
    }

    return true;
}

//
//  Write raw data and with given tag the to ASN.1 structure.
//
static size_t
vscf_asn1wr_write_tag_data(vscf_asn1wr_t *asn1wr, vsc_data_t data, int tag) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(data.bytes);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    size_t size = 0;
    size += vscf_asn1wr_write_data(asn1wr, data);
    size += vscf_asn1wr_write_len(asn1wr, data.len);
    size += vscf_asn1wr_write_tag(asn1wr, tag);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    return size;
}

//
//  Get length of the current ASN.1 element with tag and length itself.
//
static size_t
vscf_asn1wr_get_current_element_len(byte *curr, const byte *end) {

    VSCF_ASSERT_PTR(curr);
    VSCF_ASSERT_PTR(end);
    VSCF_ASSERT(curr < end + 1);

    byte *len_p = curr + 1;
    size_t len = 0;

    int status = mbedtls_asn1_get_len(&len_p, end, &len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    return (size_t)(len_p - curr) + len;
}

//
//  Swap positions of the given ASN.1 elements.
//  Note, "from" element must be behind "to" element.
//  Note, algorithm complexity is O^2.
//
static void
vscf_asn1wr_swap_elements_of_set(byte *to_start, size_t to_len, byte *from_start, size_t from_len) {

    VSCF_ASSERT_PTR(to_start);
    VSCF_ASSERT(to_len > 1);
    VSCF_ASSERT_PTR(from_start);
    VSCF_ASSERT(from_len > 1);
    VSCF_ASSERT(to_start < from_start);

    for (const byte *from_end = from_start + from_len; from_start < from_end; ++from_start, ++to_start) {
        byte temp = *from_start;

        for (byte *curr = from_start; curr > to_start; --curr) {
            *curr = *(curr - 1);
        }

        *to_start = temp;
    }
}

//
//  Return true if second element is lexicographical less then first.
//
static bool
vscf_asn1wr_second_element_of_set_is_less(
        const byte *first_start, size_t first_len, const byte *second_start, size_t second_len) {

    VSCF_ASSERT_PTR(first_start);
    VSCF_ASSERT_PTR(first_len > 1);
    VSCF_ASSERT_PTR(second_start);
    VSCF_ASSERT_PTR(second_len > 1);
    VSCF_ASSERT(first_start < second_start);

    size_t common_len = first_len < second_len ? first_len : second_len;

    const int common_cmp_result = memcmp(first_start, second_start, common_len);
    if (common_cmp_result < 0) {
        return false;

    } else if (common_cmp_result > 0) {
        return true;

    } else {
        return first_len > second_len;
    }
}

//
//  Perform lexicographical sorting of the given elements of set.
//
static void
vscf_asn1wr_sort_elements_of_set(vscf_asn1wr_t *asn1wr, size_t len) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(len <= vscf_asn1wr_written_len(asn1wr));

    const byte *end = asn1wr->curr + len;
    byte *curr_start = asn1wr->curr;

    while (curr_start < end) {
        size_t curr_len = vscf_asn1wr_get_current_element_len(curr_start, end);

        //
        //  Find min.
        //
        byte *min_start = curr_start;
        size_t min_len = curr_len;

        byte *next_start = curr_start + curr_len;
        while (next_start < end) {
            size_t next_len = vscf_asn1wr_get_current_element_len(next_start, end);

            if (vscf_asn1wr_second_element_of_set_is_less(min_start, min_len, next_start, next_len)) {
                min_start = next_start;
                min_len = next_len;
            }

            next_start += next_len;
        }

        //
        //  Insert min to the current position.
        //
        if (curr_start != min_start) {
            vscf_asn1wr_swap_elements_of_set(curr_start, curr_len, min_start, min_len);
            curr_len = min_len;
        }

        //
        //  Move forward.
        //
        curr_start += curr_len;
    }
}

//
//  Reset all internal states and prepare to new ASN.1 writing operations.
//
VSCF_PUBLIC void
vscf_asn1wr_reset(vscf_asn1wr_t *asn1wr, byte *out, size_t out_len) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(out_len > 0);

    asn1wr->start = out;
    asn1wr->end = out + out_len;
    asn1wr->curr = out + out_len;
    asn1wr->error = vscf_SUCCESS;
}

//
//  Release a target buffer.
//
VSCF_PUBLIC void
vscf_asn1wr_release(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);

    asn1wr->start = NULL;
    asn1wr->curr = NULL;
    asn1wr->error = vscf_error_UNINITIALIZED;
}

//
//  Move written data to the buffer beginning and forbid further operations.
//  Returns written size in bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_finish(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(asn1wr->error == vscf_SUCCESS);

    size_t size = (size_t)(asn1wr->end - asn1wr->curr);

    if (asn1wr->start < asn1wr->curr) {
        memmove(asn1wr->start, asn1wr->curr, size);
    }

    vscf_asn1wr_init_ctx(asn1wr);

    return size;
}

//
//  Returns pointer to the inner buffer.
//
VSCF_PUBLIC byte *
vscf_asn1wr_bytes(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(asn1wr->error != vscf_error_UNINITIALIZED);

    return asn1wr->start;
}

//
//  Returns total inner buffer length.
//
VSCF_PUBLIC size_t
vscf_asn1wr_len(const vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(asn1wr->error != vscf_error_UNINITIALIZED);

    size_t len = (size_t)(asn1wr->end - asn1wr->start);

    return len;
}

//
//  Returns how many bytes were already written to the ASN.1 structure.
//
VSCF_PUBLIC size_t
vscf_asn1wr_written_len(const vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(asn1wr->error == vscf_SUCCESS);

    size_t len = (size_t)(asn1wr->end - asn1wr->curr);
    return len;
}

//
//  Returns how many bytes are available for writing.
//
VSCF_PUBLIC size_t
vscf_asn1wr_unwritten_len(const vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(asn1wr->error == vscf_SUCCESS);

    size_t len = vscf_asn1wr_len(asn1wr) - vscf_asn1wr_written_len(asn1wr);

    return len;
}

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1wr_error(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);

    return asn1wr->error;
}

//
//  Move writing position backward for the given length.
//  Return current writing position.
//
VSCF_PUBLIC byte *
vscf_asn1wr_reserve(vscf_asn1wr_t *asn1wr, size_t len) {

    VSCF_ASSERT_PTR(asn1wr);

    if (asn1wr->start > asn1wr->curr - len) {
        asn1wr->error = vscf_error_SMALL_BUFFER;
        return NULL;
    }

    asn1wr->curr -= len;
    return asn1wr->curr;
}

//
//  Write ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_tag(vscf_asn1wr_t *asn1wr, int tag) {

    VSCF_ASSERT_PTR(asn1wr);

    VSCF_ASSERT(tag > 0);
    VSCF_ASSERT(tag <= 0xFF);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_tag(&asn1wr->curr, asn1wr->start, (unsigned char)tag);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write context-specific ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_context_tag(vscf_asn1wr_t *asn1wr, int tag, size_t len) {

    VSCF_ASSERT_PTR(asn1wr);

    VSCF_ASSERT(tag <= 0x1E);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    size_t total_len = 0;
    total_len += vscf_asn1wr_write_len(asn1wr, len);
    total_len += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    return total_len;
}

//
//  Write length of the following data.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_len(vscf_asn1wr_t *asn1wr, size_t len) {

    VSCF_ASSERT_PTR(asn1wr);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_len(&asn1wr->curr, asn1wr->start, len);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int(vscf_asn1wr_t *asn1wr, int value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_int64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int8(vscf_asn1wr_t *asn1wr, int8_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_int64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int16(vscf_asn1wr_t *asn1wr, int16_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_int64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int32(vscf_asn1wr_t *asn1wr, int32_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_int64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int64(vscf_asn1wr_t *asn1wr, int64_t value) {

    // Improved implementation taken from MbedTLS PR.
    //
    // a better world:
    //
    // the loop below terminates after at most sizeof(int)+1 iterations:
    // because of
    //
    //    P >> (8 * sizeof(int)) == 0 for all P >= 0
    // and
    //    N >> (8 * sizeof(int)) == -1 for all N < 0
    //
    // it is valid to encode and then right shift 8 bits until the result
    // of the shift operation is either 0 or -1.
    //
    // since ASN.1 BER/DER Integer encoding is specified as
    // two's complement, MSB of leading payload octet must be
    // 1 for negative and 0 for non-negative integers.
    //
    // 7 bit right shift of value and check for 0 or -1 as termination
    // condition ensures that a padding octet is written if the
    // MSB of the encoded octet does not match the sign of
    // the input.
    //
    //  for (;;)
    //  {
    //      if(*p - start < 1)
    //          return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);
    //      *--(*p) = (unsigned char)(value & 0xFF);
    //      len += 1;
    //
    //      if(value >> 7 == 0 || value >> 7 == -1)
    //          break;
    //
    //      value >>= 8;
    //  }
    //
    // reality:
    //
    // 1) Arithmethic right shift on signed integers is
    //    implementation-defined behaviour for negative integers.
    //
    // one can emulate arithmetic right shift with sign extension for
    // negative input by using a logical right shift and then set the
    // shifted-in bits to one.
    //
    // but since
    // 2) The ISO C standard allows three encoding methods for signed
    //    integers: two's complement, one's complement and sign/magnitude.
    //
    // the two's complement encoding has to be ensured.
    //

    VSCF_ASSERT_PTR(asn1wr);

    size_t len = 0;
    unsigned char **p = &asn1wr->curr;
    unsigned char *start = asn1wr->start;

    uint64_t v, fix7, fix8, cmp;

    if (value < 0) {
        v = ~((uint64_t)-value) + 1;
        fix7 = 0xFE00000000000000;
        fix8 = 0xFF00000000000000;
        cmp = -1;
    } else {
        v = (uint64_t)value;
        fix7 = 0;
        fix8 = 0;
        cmp = 0;
    }

    for (;;) {
        if (*p - start < 1) {
            asn1wr->error = vscf_error_SMALL_BUFFER;
            return 0;
        }

        *--(*p) = (unsigned char)(v & 0xFF);
        len += 1;

        if ((v >> 7 | fix7) == cmp) {
            break;
        }

        v = v >> 8 | fix8;
    }

    len += vscf_asn1wr_write_len(asn1wr, len);
    len += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_INTEGER);

    if (vscf_asn1wr_error(asn1wr) != vscf_SUCCESS) {
        return 0;
    }

    return len;
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint(vscf_asn1wr_t *asn1wr, unsigned int value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_uint64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint8(vscf_asn1wr_t *asn1wr, uint8_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_uint64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint16(vscf_asn1wr_t *asn1wr, uint16_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_uint64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint32(vscf_asn1wr_t *asn1wr, uint32_t value) {

    VSCF_ASSERT_PTR(asn1wr);

    return vscf_asn1wr_write_uint64(asn1wr, value);
}

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint64(vscf_asn1wr_t *asn1wr, uint64_t value) {

    //  Short version of vscf_asn1wr_write_int64() function.
    //  In assumption that given value is unsigned.

    VSCF_ASSERT_PTR(asn1wr);

    size_t len = 0;
    unsigned char **p = &asn1wr->curr;
    unsigned char *start = asn1wr->start;

    for (;;) {
        if (*p - start < 1) {
            asn1wr->error = vscf_error_SMALL_BUFFER;
            return 0;
        }

        *--(*p) = (unsigned char)(value & 0xFF);
        len += 1;

        if ((value >> 7) == 0) {
            break;
        }

        value = value >> 8;
    }

    len += vscf_asn1wr_write_len(asn1wr, len);
    len += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_INTEGER);

    if (vscf_asn1wr_error(asn1wr) != vscf_SUCCESS) {
        return 0;
    }

    return len;
}

//
//  Write ASN.1 type: BOOLEAN.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_bool(vscf_asn1wr_t *asn1wr, bool value) {

    VSCF_ASSERT_PTR(asn1wr);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_bool(&asn1wr->curr, asn1wr->start, value);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: NULL.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_null(vscf_asn1wr_t *asn1wr) {

    VSCF_ASSERT_PTR(asn1wr);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    int ret = mbedtls_asn1_write_null(&asn1wr->curr, asn1wr->start);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr, ret)) {
        return 0;
    }

    return (size_t)ret;
}

//
//  Write ASN.1 type: OCTET STRING.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_octet_str(vscf_asn1wr_t *asn1wr, vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_tag_data(asn1wr, value, MBEDTLS_ASN1_OCTET_STRING);
}

//
//  Write ASN.1 type: BIT STRING with all zero unused bits.
//
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_octet_str_as_bitstring(vscf_asn1wr_t *asn1wr, vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(vsc_data_is_valid(value));

    size_t written_count = vscf_asn1wr_write_data(asn1wr, value);

    if (asn1wr->error != vscf_SUCCESS) {
        return 0;
    }

    if (*asn1wr->curr != 0x00) {
        byte zero_byte = 0x00;
        written_count += vscf_asn1wr_write_data(asn1wr, vsc_data(&zero_byte, 1));
    }

    written_count += vscf_asn1wr_write_len(asn1wr, written_count);
    written_count += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_BIT_STRING);

    return written_count;
}

//
//  Write raw data directly to the ASN.1 structure.
//  Return count of written bytes.
//  Note, use this method carefully.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_data(vscf_asn1wr_t *asn1wr, vsc_data_t data) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT(vsc_data_is_valid(data));

    int ret = mbedtls_asn1_write_raw_buffer(&asn1wr->curr, asn1wr->start, data.bytes, data.len);

    if (vscf_asn1wr_mbedtls_has_error(asn1wr, ret)) {
        return 0;
    }

    return data.len;
}

//
//  Write ASN.1 type: UTF8String.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_utf8_str(vscf_asn1wr_t *asn1wr, vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_tag_data(asn1wr, value, MBEDTLS_ASN1_UTF8_STRING);
}

//
//  Write ASN.1 type: OID.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_oid(vscf_asn1wr_t *asn1wr, vsc_data_t value) {

    VSCF_ASSERT_PTR(asn1wr);
    VSCF_ASSERT_PTR(value.bytes);

    return vscf_asn1wr_write_tag_data(asn1wr, value, MBEDTLS_ASN1_OID);
}

//
//  Mark previously written data of given length as ASN.1 type: SQUENCE.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_sequence(vscf_asn1wr_t *asn1wr, size_t len) {

    VSCF_ASSERT_PTR(asn1wr);

    size_t result_len = 0;

    result_len += vscf_asn1wr_write_len(asn1wr, len);
    result_len += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    return result_len;
}

//
//  Mark previously written data of given length as ASN.1 type: SET.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_set(vscf_asn1wr_t *asn1wr, size_t len) {

    size_t result_len = 0;

    //
    //  ASN.1 SET elements must be sorted in lexicographical order.
    //
    vscf_asn1wr_sort_elements_of_set(asn1wr, len);

    result_len += vscf_asn1wr_write_len(asn1wr, len);
    result_len += vscf_asn1wr_write_tag(asn1wr, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

    return result_len;
}
