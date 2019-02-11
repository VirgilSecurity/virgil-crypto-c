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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_asn1wr_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1_writer_api.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_asn1wr_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'asn1 writer api'.
//
static const vscf_asn1_writer_api_t asn1_writer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_writer' MUST be equal to the 'vscf_api_tag_ASN1_WRITER'.
    //
    vscf_api_tag_ASN1_WRITER,
    //
    //  Reset all internal states and prepare to new ASN.1 writing operations.
    //
    (vscf_asn1_writer_api_reset_fn)vscf_asn1wr_reset,
    //
    //  Release a target buffer.
    //
    (vscf_asn1_writer_api_release_fn)vscf_asn1wr_release,
    //
    //  Move written data to the buffer beginning and forbid further operations.
    //  Returns written size in bytes.
    //
    (vscf_asn1_writer_api_finish_fn)vscf_asn1wr_finish,
    //
    //  Returns pointer to the inner buffer.
    //
    (vscf_asn1_writer_api_bytes_fn)vscf_asn1wr_bytes,
    //
    //  Returns total inner buffer length.
    //
    (vscf_asn1_writer_api_len_fn)vscf_asn1wr_len,
    //
    //  Returns how many bytes were already written to the ASN.1 structure.
    //
    (vscf_asn1_writer_api_written_len_fn)vscf_asn1wr_written_len,
    //
    //  Returns how many bytes are available for writing.
    //
    (vscf_asn1_writer_api_unwritten_len_fn)vscf_asn1wr_unwritten_len,
    //
    //  Return last error.
    //
    (vscf_asn1_writer_api_error_fn)vscf_asn1wr_error,
    //
    //  Move writing position backward for the given length.
    //  Return current writing position.
    //
    (vscf_asn1_writer_api_reserve_fn)vscf_asn1wr_reserve,
    //
    //  Write ASN.1 tag.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_tag_fn)vscf_asn1wr_write_tag,
    //
    //  Write context-specific ASN.1 tag.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_context_tag_fn)vscf_asn1wr_write_context_tag,
    //
    //  Write length of the following data.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_len_fn)vscf_asn1wr_write_len,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_int_fn)vscf_asn1wr_write_int,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_int8_fn)vscf_asn1wr_write_int8,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_int16_fn)vscf_asn1wr_write_int16,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_int32_fn)vscf_asn1wr_write_int32,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_int64_fn)vscf_asn1wr_write_int64,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_uint_fn)vscf_asn1wr_write_uint,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_uint8_fn)vscf_asn1wr_write_uint8,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_uint16_fn)vscf_asn1wr_write_uint16,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_uint32_fn)vscf_asn1wr_write_uint32,
    //
    //  Write ASN.1 type: INTEGER.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_uint64_fn)vscf_asn1wr_write_uint64,
    //
    //  Write ASN.1 type: BOOLEAN.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_bool_fn)vscf_asn1wr_write_bool,
    //
    //  Write ASN.1 type: NULL.
    //
    (vscf_asn1_writer_api_write_null_fn)vscf_asn1wr_write_null,
    //
    //  Write ASN.1 type: OCTET STRING.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_octet_str_fn)vscf_asn1wr_write_octet_str,
    //
    //  Write ASN.1 type: BIT STRING with all zero unused bits.
    //
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_octet_str_as_bitstring_fn)vscf_asn1wr_write_octet_str_as_bitstring,
    //
    //  Write raw data directly to the ASN.1 structure.
    //  Return count of written bytes.
    //  Note, use this method carefully.
    //
    (vscf_asn1_writer_api_write_data_fn)vscf_asn1wr_write_data,
    //
    //  Write ASN.1 type: UTF8String.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_utf8_str_fn)vscf_asn1wr_write_utf8_str,
    //
    //  Write ASN.1 type: OID.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_oid_fn)vscf_asn1wr_write_oid,
    //
    //  Mark previously written data of given length as ASN.1 type: SQUENCE.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_sequence_fn)vscf_asn1wr_write_sequence,
    //
    //  Mark previously written data of given length as ASN.1 type: SET.
    //  Return count of written bytes.
    //
    (vscf_asn1_writer_api_write_set_fn)vscf_asn1wr_write_set
};

//
//  Compile-time known information about 'asn1wr' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_asn1wr_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_asn1wr_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_asn1wr_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_asn1wr_init(vscf_asn1wr_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_asn1wr_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_asn1wr_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_init()'.
//
VSCF_PUBLIC void
vscf_asn1wr_cleanup(vscf_asn1wr_t *self) {

    if (self == NULL || self->info == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt > 0) {
        return;
    }

    vscf_asn1wr_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_asn1wr_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_asn1wr_t *
vscf_asn1wr_new(void) {

    vscf_asn1wr_t *self = (vscf_asn1wr_t *) vscf_alloc(sizeof (vscf_asn1wr_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_asn1wr_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_new()'.
//
VSCF_PUBLIC void
vscf_asn1wr_delete(vscf_asn1wr_t *self) {

    vscf_asn1wr_cleanup(self);

    if (self && (self->refcnt == 0)) {
        vscf_dealloc(self);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_asn1wr_destroy(vscf_asn1wr_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_asn1wr_t *self = *self_ref;
    *self_ref = NULL;

    vscf_asn1wr_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_asn1wr_t *
vscf_asn1wr_shallow_copy(vscf_asn1wr_t *self) {

    // Proxy to the parent implementation.
    return (vscf_asn1wr_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_asn1wr_t' type.
//
VSCF_PUBLIC size_t
vscf_asn1wr_impl_size(void) {

    return sizeof (vscf_asn1wr_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_asn1wr_impl(vscf_asn1wr_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_asn1wr_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ASN1_WRITER:
            return (const vscf_api_t *) &asn1_writer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
