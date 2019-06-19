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

#include "vscf_asn1rd_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_reader_api.h"
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
vscf_asn1rd_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'asn1 reader api'.
//
static const vscf_asn1_reader_api_t asn1_reader_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'asn1_reader' MUST be equal to the 'vscf_api_tag_ASN1_READER'.
    //
    vscf_api_tag_ASN1_READER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ASN1RD,
    //
    //  Reset all internal states and prepare to new ASN.1 reading operations.
    //
    (vscf_asn1_reader_api_reset_fn)vscf_asn1rd_reset,
    //
    //  Return length in bytes how many bytes are left for reading.
    //
    (vscf_asn1_reader_api_left_len_fn)vscf_asn1rd_left_len,
    //
    //  Return true if status is not "success".
    //
    (vscf_asn1_reader_api_has_error_fn)vscf_asn1rd_has_error,
    //
    //  Return error code.
    //
    (vscf_asn1_reader_api_status_fn)vscf_asn1rd_status,
    //
    //  Get tag of the current ASN.1 element.
    //
    (vscf_asn1_reader_api_get_tag_fn)vscf_asn1rd_get_tag,
    //
    //  Get length of the current ASN.1 element.
    //
    (vscf_asn1_reader_api_get_len_fn)vscf_asn1rd_get_len,
    //
    //  Get length of the current ASN.1 element with tag and length itself.
    //
    (vscf_asn1_reader_api_get_data_len_fn)vscf_asn1rd_get_data_len,
    //
    //  Read ASN.1 type: TAG.
    //  Return element length.
    //
    (vscf_asn1_reader_api_read_tag_fn)vscf_asn1rd_read_tag,
    //
    //  Read ASN.1 type: context-specific TAG.
    //  Return element length.
    //  Return 0 if current position do not points to the requested tag.
    //
    (vscf_asn1_reader_api_read_context_tag_fn)vscf_asn1rd_read_context_tag,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_int_fn)vscf_asn1rd_read_int,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_int8_fn)vscf_asn1rd_read_int8,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_int16_fn)vscf_asn1rd_read_int16,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_int32_fn)vscf_asn1rd_read_int32,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_int64_fn)vscf_asn1rd_read_int64,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_uint_fn)vscf_asn1rd_read_uint,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_uint8_fn)vscf_asn1rd_read_uint8,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_uint16_fn)vscf_asn1rd_read_uint16,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_uint32_fn)vscf_asn1rd_read_uint32,
    //
    //  Read ASN.1 type: INTEGER.
    //
    (vscf_asn1_reader_api_read_uint64_fn)vscf_asn1rd_read_uint64,
    //
    //  Read ASN.1 type: BOOLEAN.
    //
    (vscf_asn1_reader_api_read_bool_fn)vscf_asn1rd_read_bool,
    //
    //  Read ASN.1 type: NULL.
    //
    (vscf_asn1_reader_api_read_null_fn)vscf_asn1rd_read_null,
    //
    //  Read ASN.1 type: NULL, only if it exists.
    //  Note, this method is safe to call even no more data is left for reading.
    //
    (vscf_asn1_reader_api_read_null_optional_fn)vscf_asn1rd_read_null_optional,
    //
    //  Read ASN.1 type: OCTET STRING.
    //
    (vscf_asn1_reader_api_read_octet_str_fn)vscf_asn1rd_read_octet_str,
    //
    //  Read ASN.1 type: BIT STRING.
    //
    (vscf_asn1_reader_api_read_bitstring_as_octet_str_fn)vscf_asn1rd_read_bitstring_as_octet_str,
    //
    //  Read ASN.1 type: UTF8String.
    //
    (vscf_asn1_reader_api_read_utf8_str_fn)vscf_asn1rd_read_utf8_str,
    //
    //  Read ASN.1 type: OID.
    //
    (vscf_asn1_reader_api_read_oid_fn)vscf_asn1rd_read_oid,
    //
    //  Read raw data of given length.
    //
    (vscf_asn1_reader_api_read_data_fn)vscf_asn1rd_read_data,
    //
    //  Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    //  Return element length.
    //
    (vscf_asn1_reader_api_read_sequence_fn)vscf_asn1rd_read_sequence,
    //
    //  Read ASN.1 type: CONSTRUCTED | SET.
    //  Return element length.
    //
    (vscf_asn1_reader_api_read_set_fn)vscf_asn1rd_read_set
};

//
//  Compile-time known information about 'asn1rd' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_ASN1RD,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_asn1rd_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_asn1rd_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_asn1rd_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_asn1rd_init(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_asn1rd_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_asn1rd_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_init()'.
//
VSCF_PUBLIC void
vscf_asn1rd_cleanup(vscf_asn1rd_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_asn1rd_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_asn1rd_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_asn1rd_t *
vscf_asn1rd_new(void) {

    vscf_asn1rd_t *self = (vscf_asn1rd_t *) vscf_alloc(sizeof (vscf_asn1rd_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_asn1rd_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_new()'.
//
VSCF_PUBLIC void
vscf_asn1rd_delete(vscf_asn1rd_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if ((new_counter > 0) || (0 == old_counter)) {
        return;
    }

    vscf_asn1rd_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1rd_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_asn1rd_destroy(vscf_asn1rd_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_asn1rd_t *self = *self_ref;
    *self_ref = NULL;

    vscf_asn1rd_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_asn1rd_t *
vscf_asn1rd_shallow_copy(vscf_asn1rd_t *self) {

    // Proxy to the parent implementation.
    return (vscf_asn1rd_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_asn1rd_t' type.
//
VSCF_PUBLIC size_t
vscf_asn1rd_impl_size(void) {

    return sizeof (vscf_asn1rd_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_asn1rd_impl(vscf_asn1rd_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

static const vscf_api_t *
vscf_asn1rd_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ASN1_READER:
            return (const vscf_api_t *) &asn1_reader_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
