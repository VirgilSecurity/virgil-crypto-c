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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_info_der_serializer_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_message_info_der_serializer_defs.h"
#include "vscf_message_info_serializer.h"
#include "vscf_message_info_serializer_api.h"
#include "vscf_message_info_footer_serializer.h"
#include "vscf_message_info_footer_serializer_api.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  This method is called when interface 'asn1 reader' was setup.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_setup_asn1_reader(vscf_message_info_der_serializer_t *self);

//
//  This method is called when interface 'asn1 reader' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_reader(vscf_message_info_der_serializer_t *self);

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_setup_asn1_writer(vscf_message_info_der_serializer_t *self);

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_message_info_der_serializer_did_release_asn1_writer(vscf_message_info_der_serializer_t *self);

static const vscf_api_t *
vscf_message_info_der_serializer_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'message info serializer api'.
//
static const vscf_message_info_serializer_api_t message_info_serializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'message_info_serializer' MUST be equal to the 'vscf_api_tag_MESSAGE_INFO_SERIALIZER'.
    //
    vscf_api_tag_MESSAGE_INFO_SERIALIZER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER,
    //
    //  Return buffer size enough to hold serialized message info.
    //
    (vscf_message_info_serializer_api_serialized_len_fn)vscf_message_info_der_serializer_serialized_len,
    //
    //  Serialize class "message info".
    //
    (vscf_message_info_serializer_api_serialize_fn)vscf_message_info_der_serializer_serialize,
    //
    //  Read message info prefix from the given data, and if it is valid,
    //  return a length of bytes of the whole message info.
    //
    //  Zero returned if length can not be determined from the given data,
    //  and this means that there is no message info at the data beginning.
    //
    (vscf_message_info_serializer_api_read_prefix_fn)vscf_message_info_der_serializer_read_prefix,
    //
    //  Deserialize class "message info".
    //
    (vscf_message_info_serializer_api_deserialize_fn)vscf_message_info_der_serializer_deserialize,
    vscf_message_info_der_serializer_PREFIX_LEN
};

//
//  Configuration of the interface API 'message info footer serializer api'.
//
static const vscf_message_info_footer_serializer_api_t message_info_footer_serializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'message_info_footer_serializer' MUST be equal to the 'vscf_api_tag_MESSAGE_INFO_FOOTER_SERIALIZER'.
    //
    vscf_api_tag_MESSAGE_INFO_FOOTER_SERIALIZER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER,
    //
    //  Return buffer size enough to hold serialized message info footer.
    //
    (vscf_message_info_footer_serializer_api_serialized_footer_len_fn)vscf_message_info_der_serializer_serialized_footer_len,
    //
    //  Serialize class "message info footer".
    //
    (vscf_message_info_footer_serializer_api_serialize_footer_fn)vscf_message_info_der_serializer_serialize_footer,
    //
    //  Deserialize class "message info footer".
    //
    (vscf_message_info_footer_serializer_api_deserialize_footer_fn)vscf_message_info_der_serializer_deserialize_footer
};

//
//  Compile-time known information about 'message info der serializer' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_MESSAGE_INFO_DER_SERIALIZER,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_message_info_der_serializer_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_message_info_der_serializer_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_message_info_der_serializer_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_init(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_info_der_serializer_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_message_info_der_serializer_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_init()'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_cleanup(vscf_message_info_der_serializer_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_message_info_der_serializer_release_asn1_reader(self);
    vscf_message_info_der_serializer_release_asn1_writer(self);

    vscf_message_info_der_serializer_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_message_info_der_serializer_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_message_info_der_serializer_t *
vscf_message_info_der_serializer_new(void) {

    vscf_message_info_der_serializer_t *self = (vscf_message_info_der_serializer_t *) vscf_alloc(sizeof (vscf_message_info_der_serializer_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_info_der_serializer_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_new()'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_delete(vscf_message_info_der_serializer_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_message_info_der_serializer_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_message_info_der_serializer_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_destroy(vscf_message_info_der_serializer_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_info_der_serializer_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_info_der_serializer_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_info_der_serializer_t *
vscf_message_info_der_serializer_shallow_copy(vscf_message_info_der_serializer_t *self) {

    // Proxy to the parent implementation.
    return (vscf_message_info_der_serializer_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_message_info_der_serializer_t' type.
//
VSCF_PUBLIC size_t
vscf_message_info_der_serializer_impl_size(void) {

    return sizeof (vscf_message_info_der_serializer_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_message_info_der_serializer_impl(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_message_info_der_serializer_impl_const(const vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_use_asn1_reader(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT(self->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    self->asn1_reader = vscf_impl_shallow_copy(asn1_reader);

    vscf_message_info_der_serializer_did_setup_asn1_reader(self);
}

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_take_asn1_reader(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT(self->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    self->asn1_reader = asn1_reader;

    vscf_message_info_der_serializer_did_setup_asn1_reader(self);
}

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_release_asn1_reader(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->asn1_reader);

    vscf_message_info_der_serializer_did_release_asn1_reader(self);
}

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_use_asn1_writer(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT(self->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    self->asn1_writer = vscf_impl_shallow_copy(asn1_writer);

    vscf_message_info_der_serializer_did_setup_asn1_writer(self);
}

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_take_asn1_writer(vscf_message_info_der_serializer_t *self, vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT(self->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    self->asn1_writer = asn1_writer;

    vscf_message_info_der_serializer_did_setup_asn1_writer(self);
}

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_message_info_der_serializer_release_asn1_writer(vscf_message_info_der_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->asn1_writer);

    vscf_message_info_der_serializer_did_release_asn1_writer(self);
}

static const vscf_api_t *
vscf_message_info_der_serializer_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_MESSAGE_INFO_FOOTER_SERIALIZER:
            return (const vscf_api_t *) &message_info_footer_serializer_api;
        case vscf_api_tag_MESSAGE_INFO_SERIALIZER:
            return (const vscf_api_t *) &message_info_serializer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
