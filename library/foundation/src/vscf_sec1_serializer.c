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
//  This module contains 'sec1 serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_sec1_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_asn1_tag.h"
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_alg_info_der_serializer.h"
#include "vscf_ec_alg_info.h"
#include "vscf_asn1_writer.h"
#include "vscf_sec1_serializer_defs.h"
#include "vscf_sec1_serializer_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return true if given key is an Elliptic Curve key defined in the SEC 1.
//
static bool
vscf_sec1_serializer_is_ec_key(const vscf_impl_t *key);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_sec1_serializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_sec1_serializer_init_ctx(vscf_sec1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_info_der_serializer = vscf_alg_info_der_serializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_sec1_serializer_cleanup_ctx(vscf_sec1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_destroy(&self->alg_info_der_serializer);
}

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE void
vscf_sec1_serializer_did_setup_asn1_writer(vscf_sec1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_release_asn1_writer(self->alg_info_der_serializer);
    vscf_alg_info_der_serializer_use_asn1_writer(self->alg_info_der_serializer, self->asn1_writer);
}

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_sec1_serializer_did_release_asn1_writer(vscf_sec1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_release_asn1_writer(self->alg_info_der_serializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_sec1_serializer_setup_defaults(vscf_sec1_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_writer) {
        vscf_sec1_serializer_take_asn1_writer(self, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }
}

//
//  Serialize Public Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialize_public_key_inplace(
        vscf_sec1_serializer_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //          algorithm AlgorithmIdentifier,
    //          subjectPublicKey BIT STRING
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_sec1_serializer_is_ec_key(public_key));
    VSCF_ASSERT(vscf_public_key_can_export_public_key(vscf_public_key_api(public_key)));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_sec1_serializer_serialized_public_key_len(self, public_key));

    if (error && vscf_error_has_error(error)) {
        return 0;
    }

    size_t len = 0;

    //
    //  Write key
    //
    vsc_buffer_t *exported_key = vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));
    vscf_status_t status = vscf_public_key_export_public_key(public_key, exported_key);

    len += vscf_asn1_writer_write_octet_str_as_bitstring(self->asn1_writer, vsc_buffer_data(exported_key));

    vsc_buffer_destroy(&exported_key);

    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return 0;
    }

    //
    //  Write algorithm
    //
    vscf_impl_t *alg_info = vscf_alg_produce_alg_info(public_key);
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_der_serializer, alg_info);
    vscf_impl_destroy(&alg_info);

    //
    //  Write SubjectPublicKeyInfo
    //
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    //
    //  Finalize
    //
    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1_writer));

    return len;
}

//
//  Serialize Private Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialize_private_key_inplace(
        vscf_sec1_serializer_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    //  ECPrivateKey ::= SEQUENCE {
    //      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //      privateKey OCTET STRING,
    //      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //      publicKey [1] BIT STRING OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_private_key_can_export_private_key(vscf_private_key_api(private_key)));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_sec1_serializer_serialized_private_key_len(self, private_key));

    if (error && vscf_error_has_error(error)) {
        return 0;
    }

    size_t len = 0;

    //
    //  Write publicKey[1]
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));

    vscf_status_t status = vscf_public_key_export_public_key(public_key, exported_public_key);
    VSCF_ASSERT(status == vscf_status_SUCCESS);

    size_t public_key_written_len =
            vscf_asn1_writer_write_octet_str_as_bitstring(self->asn1_writer, vsc_buffer_data(exported_public_key));

    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&exported_public_key);
    len += public_key_written_len + vscf_asn1_writer_write_context_tag(self->asn1_writer, 1, public_key_written_len);

    //
    //  Write parameters[0]
    //
    vscf_impl_t *alg_info = vscf_alg_produce_alg_info(private_key);
    VSCF_ASSERT(vscf_impl_tag(alg_info) == vscf_impl_tag_EC_ALG_INFO);
    const vscf_oid_id_t named_curve_id = vscf_ec_alg_info_domain_id((const vscf_ec_alg_info_t *)alg_info);
    vscf_impl_destroy(&alg_info);

    vsc_data_t named_curve_oid = vscf_oid_from_id(named_curve_id);
    size_t named_curve_written_len = vscf_asn1_writer_write_oid(self->asn1_writer, named_curve_oid);
    len += named_curve_written_len + vscf_asn1_writer_write_context_tag(self->asn1_writer, 0, named_curve_written_len);

    //
    //  Write key
    //
    vsc_buffer_t *exported_key = vsc_buffer_new_with_capacity(vscf_private_key_exported_private_key_len(private_key));
    status = vscf_private_key_export_private_key(private_key, exported_key);
    VSCF_ASSERT(status == vscf_status_SUCCESS);

    len += vscf_asn1_writer_write_octet_str(self->asn1_writer, vsc_buffer_data(exported_key));

    vsc_buffer_destroy(&exported_key);

    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return 0;
    }

    //
    //  Write version
    //
    len += vscf_asn1_writer_write_int(self->asn1_writer, 1);

    //
    //  Write ECPrivateKey
    //
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    //
    //  Finalize
    //
    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1_writer));

    return len;
}

//
//  Return true if given key is an Elliptic Curve key defined in the SEC 1.
//
static bool
vscf_sec1_serializer_is_ec_key(const vscf_impl_t *key) {

    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_alg_is_implemented(key));

    vscf_alg_id_t alg_id = vscf_alg_alg_id(key);

    switch (alg_id) {
    case vscf_alg_id_SECP256R1:
        return true;
    default:
        return false;
    }
}

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialized_public_key_len(vscf_sec1_serializer_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_public_key_can_export_public_key(vscf_public_key_api(public_key)));

    size_t wrappedKeyLen = vscf_public_key_exported_public_key_len(public_key);
    size_t len = 1 + 4 +                //  SubjectPublicKeyInfo ::= SEQUENCE {
                 1 + 1 + 32 +           //          algorithm AlgorithmIdentifier,
                 1 + 4 + wrappedKeyLen; //          subjectPublicKey BIT STRING
                                        //  }

    return len;
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_sec1_serializer_serialize_public_key(
        vscf_sec1_serializer_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_public_key_can_export_public_key(vscf_public_key_api(public_key)));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_sec1_serializer_serialized_public_key_len(self, public_key));
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t len = vscf_sec1_serializer_serialize_public_key_inplace(self, public_key, &error);

    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }

    vscf_asn1_writer_finish(self->asn1_writer, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);

    return vscf_status_SUCCESS;
}

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_sec1_serializer_serialized_private_key_len(vscf_sec1_serializer_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_private_key_can_export_private_key(vscf_private_key_api(private_key)));

    size_t wrappedKeyLen = vscf_private_key_exported_private_key_len(private_key);
    size_t len = 1 + 1 + 2 +                    //  ECPrivateKey ::= SEQUENCE {
                 1 + 1 + 1 +                    //      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                 1 + 1 + wrappedKeyLen +        //      privateKey OCTET STRING,
                 1 + 1 + 1 + 1 + 8 +            //      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                 1 + 1 + 2 * wrappedKeyLen + 2; //      publicKey [1] BIT STRING OPTIONAL }

    return len;
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_sec1_serializer_serialize_private_key(
        vscf_sec1_serializer_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_private_key_can_export_private_key(vscf_private_key_api(private_key)));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_sec1_serializer_serialized_private_key_len(self, private_key));
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t len = vscf_sec1_serializer_serialize_private_key_inplace(self, private_key, &error);

    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }

    vscf_asn1_writer_finish(self->asn1_writer, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);

    return vscf_status_SUCCESS;
}
