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
//  Simple PEM wrapper.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pem.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_base64.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const size_t k_line_len_max = 64;

static const char *const k_header_begin = "-----BEGIN ";

static const char *const k_footer_begin = "-----END ";

static const char *const k_title_tail = "-----";


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Return length in bytes required to hold wrapped PEM format.
//
VSCF_PUBLIC size_t
vscf_pem_wrapped_len(const char *title, size_t data_len) {

    VSCF_ASSERT_PTR(title);

    size_t newline_len = 1;
    size_t header_len = strlen(k_header_begin) + strlen(title) + strlen(k_title_tail) + newline_len;
    size_t footer_len = strlen(k_footer_begin) + strlen(title) + strlen(k_title_tail) + newline_len;
    size_t base64_len = vscf_base64_encoded_len(data_len);
    size_t base64_newlines_len = newline_len * VSCF_CEIL(base64_len, k_line_len_max);

    return header_len + footer_len + base64_len + base64_newlines_len + 1 /* terminating zero*/;
}

//
//  Takes binary data and wraps it to the simple PEM format - no
//  additional information just header-base64-footer.
//  Note, written buffer is NOT null-terminated.
//
VSCF_PUBLIC void
vscf_pem_wrap(const char *title, vsc_data_t data, vsc_buffer_t *pem) {

    VSCF_ASSERT_PTR(title);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(pem);
    VSCF_ASSERT(vsc_buffer_is_valid(pem));
    VSCF_ASSERT(vsc_buffer_unused_len(pem) >= vscf_pem_wrapped_len(title, data.len));

    //
    //  Write header.
    //
    vsc_buffer_append_data(pem, vsc_data_from_str(k_header_begin, strlen(k_header_begin)));
    vsc_buffer_append_data(pem, vsc_data_from_str(title, strlen(title)));
    vsc_buffer_append_data(pem, vsc_data_from_str(k_title_tail, strlen(k_title_tail)));
    vsc_buffer_append_data(pem, vsc_data_from_str("\n", 1));

    //
    //  Write base64 formatted body.
    //
    //  TODO: Optimize memcpy.
    vsc_buffer_t *base64_buf = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(data.len));
    vscf_base64_encode(data, base64_buf);
    vsc_data_t base64 = vsc_buffer_data(base64_buf);

    for (size_t bytes_left = base64.len, read_pos = 0, str_len = 0; bytes_left > 0;
            bytes_left -= str_len, read_pos += k_line_len_max) {

        str_len = bytes_left < k_line_len_max ? bytes_left : k_line_len_max;
        vsc_data_t line = vsc_data_slice_beg(base64, read_pos, str_len);
        vsc_buffer_write_data(pem, line);
        vsc_buffer_write_data(pem, vsc_data_from_str("\n", 1));
    }

    base64 = vsc_data_empty();
    vsc_buffer_destroy(&base64_buf);

    //
    //  Write footer.
    //
    vsc_buffer_append_data(pem, vsc_data_from_str(k_footer_begin, strlen(k_footer_begin)));
    vsc_buffer_append_data(pem, vsc_data_from_str(title, strlen(title)));
    vsc_buffer_append_data(pem, vsc_data_from_str(k_title_tail, strlen(k_title_tail)));

    *vsc_buffer_unused_bytes(pem) = 0x00;
}

//
//  Return length in bytes required to hold unwrapped binary.
//
VSCF_PUBLIC size_t
vscf_pem_unwrapped_len(size_t pem_len) {

    //  TODO: Make more precise calculations.
    return pem_len;
}

//
//  Takes PEM data and extract binary data from it.
//
VSCF_PUBLIC vscf_status_t
vscf_pem_unwrap(vsc_data_t pem, vsc_buffer_t *data) {

    VSCF_ASSERT(vsc_data_is_valid(pem));
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT(vsc_buffer_is_valid(data));
    VSCF_ASSERT(vsc_buffer_unused_len(data) >= vscf_pem_unwrapped_len(pem.len));

    //
    //  Grab PEM header.
    //
    const char *header_begin = vscf_strnstr((const char *)pem.bytes, k_header_begin, pem.len);
    size_t header_index = header_begin - (const char *)pem.bytes;
    size_t header_begin_len =  strlen(k_header_begin);

    if (NULL == header_begin) {
        return vscf_status_ERROR_BAD_PEM;
    }

    const char *header_end = vscf_strnstr(header_begin + header_begin_len, k_title_tail, pem.len - header_index - header_begin_len);
    if (NULL == header_end) {
        return vscf_status_ERROR_BAD_PEM;
    }
    header_end += strlen(k_title_tail);

    //
    //  Grab PEM body.
    //
    const char *body_begin = header_end;

    if ('\r' == *body_begin) {
        ++body_begin;
    }

    if ('\n' == *body_begin) {
        ++body_begin;
    }

    //
    //  Grab PEN footer.
    //
    const char *footer_begin = vscf_strnstr((const char *)pem.bytes, k_footer_begin, pem.len);
    size_t footer_index = footer_begin - (const char *)pem.bytes;
    size_t k_footer_len = strlen(k_footer_begin);
    if (NULL == footer_begin || footer_begin < body_begin) {
        return vscf_status_ERROR_BAD_PEM;
    }

    const char *footer_end = vscf_strnstr(footer_begin + k_footer_len, k_title_tail, pem.len - footer_index - k_footer_len);
    if (NULL == footer_end) {
        return vscf_status_ERROR_BAD_PEM;
    }
    footer_end += strlen(k_title_tail);

    if (footer_end - header_begin > (ptrdiff_t)pem.len) {
        return vscf_status_ERROR_BAD_PEM;
    }

    //
    //  Decode body
    //
    vscf_status_t status = vscf_base64_decode(vsc_data_from_str(body_begin, footer_begin - body_begin), data);
    *vsc_buffer_unused_bytes(data) = 0x00;

    if (status != vscf_status_SUCCESS) {
        return vscf_status_ERROR_BAD_PEM;
    }

    return vscf_status_SUCCESS;
}

//
//  Returns PEM title if PEM data is valid, otherwise - empty data.
//
VSCF_PUBLIC vsc_data_t
vscf_pem_title(vsc_data_t pem) {

    VSCF_ASSERT(vsc_data_is_valid(pem));

    if (vsc_data_is_empty(pem)) {
        return vsc_data_empty();
    }

    size_t pem_len = pem.len;
    const char *header_begin = vscf_strnstr((const char *)pem.bytes, k_header_begin, pem_len);
    if (NULL == header_begin) {
        return vsc_data_empty();
    }

    const char *title_begin = header_begin + strlen(k_header_begin);

    const char *title_end = vscf_strnstr(title_begin, k_title_tail, pem_len - strlen(k_header_begin));
    if (NULL == title_end) {
        return vsc_data_empty();
    }

    if (title_end - header_begin > (ptrdiff_t)pem.len) {
        return vsc_data_empty();
    }

    return vsc_data_from_str(title_begin, title_end - title_begin);
}
