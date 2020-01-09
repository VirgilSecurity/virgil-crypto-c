//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  This module contains 'key asn1 serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_key_asn1_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1wr.h"
#include "vscf_pkcs8_serializer.h"
#include "vscf_sec1_serializer.h"
#include "vscf_asn1_writer.h"
#include "vscf_key_asn1_serializer_defs.h"
#include "vscf_key_asn1_serializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_key_asn1_serializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_key_asn1_serializer_init_ctx(vscf_key_asn1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);


    self->sec1_serializer = vscf_sec1_serializer_new();
    self->pkcs8_serializer = vscf_pkcs8_serializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_key_asn1_serializer_cleanup_ctx(vscf_key_asn1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->asn1_writer);
    vscf_sec1_serializer_destroy(&self->sec1_serializer);
    vscf_pkcs8_serializer_destroy(&self->pkcs8_serializer);
}

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE void
vscf_key_asn1_serializer_did_setup_asn1_writer(vscf_key_asn1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_sec1_serializer_use_asn1_writer(self->sec1_serializer, self->asn1_writer);
    vscf_pkcs8_serializer_use_asn1_writer(self->pkcs8_serializer, self->asn1_writer);
}

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_key_asn1_serializer_did_release_asn1_writer(vscf_key_asn1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_sec1_serializer_release_asn1_writer(self->sec1_serializer);
    vscf_pkcs8_serializer_release_asn1_writer(self->pkcs8_serializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_key_asn1_serializer_setup_defaults(vscf_key_asn1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_writer) {
        vscf_key_asn1_serializer_take_asn1_writer(self, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }
}

//
//  Serialize Public Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_key_asn1_serializer_serialize_public_key_inplace(
        vscf_key_asn1_serializer_t *self, const vscf_raw_public_key_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_key_asn1_serializer_serialized_public_key_len(self, public_key));

    vscf_alg_id_t alg_id = vscf_raw_public_key_alg_id(public_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialize_public_key_inplace(self->sec1_serializer, public_key, error);
    default:
        return vscf_pkcs8_serializer_serialize_public_key_inplace(self->pkcs8_serializer, public_key, error);
    }
}

//
//  Serialize Private Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_key_asn1_serializer_serialize_private_key_inplace(
        vscf_key_asn1_serializer_t *self, const vscf_raw_private_key_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_key_asn1_serializer_serialized_private_key_len(self, private_key));

    vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(private_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialize_private_key_inplace(self->sec1_serializer, private_key, error);
    default:
        return vscf_pkcs8_serializer_serialize_private_key_inplace(self->pkcs8_serializer, private_key, error);
    }
}

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_asn1_serializer_serialized_public_key_len(
        const vscf_key_asn1_serializer_t *self, const vscf_raw_public_key_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));

    vscf_alg_id_t alg_id = vscf_raw_public_key_alg_id(public_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialized_public_key_len(self->sec1_serializer, public_key);
    default:
        return vscf_pkcs8_serializer_serialized_public_key_len(self->pkcs8_serializer, public_key);
    }
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_asn1_serializer_serialize_public_key(
        vscf_key_asn1_serializer_t *self, const vscf_raw_public_key_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_key_asn1_serializer_serialized_public_key_len(self, public_key));


    vscf_alg_id_t alg_id = vscf_raw_public_key_alg_id(public_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialize_public_key(self->sec1_serializer, public_key, out);
    default:
        return vscf_pkcs8_serializer_serialize_public_key(self->pkcs8_serializer, public_key, out);
    }
}

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_key_asn1_serializer_serialized_private_key_len(
        const vscf_key_asn1_serializer_t *self, const vscf_raw_private_key_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));

    vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(private_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialized_private_key_len(self->sec1_serializer, private_key);
    default:
        return vscf_pkcs8_serializer_serialized_private_key_len(self->pkcs8_serializer, private_key);
    }
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_key_asn1_serializer_serialize_private_key(
        vscf_key_asn1_serializer_t *self, const vscf_raw_private_key_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_key_asn1_serializer_serialized_private_key_len(self, private_key));

    vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(private_key);
    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return vscf_sec1_serializer_serialize_private_key(self->sec1_serializer, private_key, out);
    default:
        return vscf_pkcs8_serializer_serialize_private_key(self->pkcs8_serializer, private_key, out);
    }
}
