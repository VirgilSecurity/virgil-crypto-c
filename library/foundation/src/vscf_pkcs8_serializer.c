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
//  This module contains 'pkcs8 serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs8_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1_tag.h"
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_writer.h"
#include "vscf_pkcs8_serializer_defs.h"
#include "vscf_pkcs8_serializer_internal.h"

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
//  Note, this method is called automatically when method vscf_pkcs8_serializer_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_init_ctx(vscf_pkcs8_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->alg_info_der_serializer = vscf_alg_info_der_serializer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_cleanup_ctx(vscf_pkcs8_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_destroy(&self->alg_info_der_serializer);
}

//
//  This method is called when interface 'asn1 writer' was setup.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_did_setup_asn1_writer(vscf_pkcs8_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_release_asn1_writer(self->alg_info_der_serializer);
    vscf_alg_info_der_serializer_use_asn1_writer(self->alg_info_der_serializer, self->asn1_writer);
}

//
//  This method is called when interface 'asn1 writer' was released.
//
VSCF_PRIVATE void
vscf_pkcs8_serializer_did_release_asn1_writer(vscf_pkcs8_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_alg_info_der_serializer_release_asn1_writer(self->alg_info_der_serializer);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC void
vscf_pkcs8_serializer_setup_defaults(vscf_pkcs8_serializer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->asn1_writer) {
        vscf_pkcs8_serializer_take_asn1_writer(self, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }
}

//
//  Serialize Public Key by using internal ASN.1 writer.
//  Note, that caller code is responsible to reset ASN.1 writer with
//  an output buffer.
//
VSCF_PUBLIC size_t
vscf_pkcs8_serializer_serialize_public_key_inplace(vscf_pkcs8_serializer_t *self,
        const vscf_raw_public_key_t *public_key, vscf_error_t *error) {

    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //          algorithm AlgorithmIdentifier,
    //          subjectPublicKey BIT STRING
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_pkcs8_serializer_serialized_public_key_len(self, public_key));

    if (error && vscf_error_has_error(error)) {
        return 0;
    }

    size_t len = 0;

    //
    //  Write key
    //
    len += vscf_asn1_writer_write_octet_str_as_bitstring(self->asn1_writer, vscf_raw_public_key_data(public_key));

    //
    //  Write algorithm
    //
    const vscf_impl_t *alg_info = vscf_raw_public_key_alg_info(public_key);
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_der_serializer, alg_info);

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
vscf_pkcs8_serializer_serialize_private_key_inplace(vscf_pkcs8_serializer_t *self,
        const vscf_raw_private_key_t *private_key, vscf_error_t *error) {

    //  PrivateKeyInfo ::= SEQUENCE {
    //          version Version,
    //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //          privateKey PrivateKey,
    //          attributes [0] IMPLICIT Attributes OPTIONAL
    //  }

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));
    VSCF_ASSERT_PTR(self->asn1_writer);
    VSCF_ASSERT(vscf_asn1_writer_unwritten_len(self->asn1_writer) >=
                vscf_pkcs8_serializer_serialized_private_key_len(self, private_key));

    if (error && vscf_error_has_error(error)) {
        return 0;
    }

    size_t len = 0;

    //
    //  Write key
    //
    size_t key_written_len =
            vscf_asn1_writer_write_octet_str(self->asn1_writer, vscf_raw_private_key_data(private_key));

    vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(private_key);
    switch (alg_id) {
    case vscf_alg_id_ED25519:
    case vscf_alg_id_CURVE25519:
        //
        //  According to RFC 8410
        //
        //  CurvePrivateKey ::= OCTET STRING
        //
        key_written_len += vscf_asn1_writer_write_len(self->asn1_writer, key_written_len);
        key_written_len += vscf_asn1_writer_write_tag(self->asn1_writer, vscf_asn1_tag_OCTET_STRING);
    default:
        break;
    }

    len += key_written_len;

    //
    //  Write algorithm
    //
    const vscf_impl_t *alg_info = vscf_raw_private_key_alg_info(private_key);
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_der_serializer, alg_info);

    //
    //  Write version
    //
    len += vscf_asn1_writer_write_int(self->asn1_writer, 0);

    //
    //  Write PrivateKeyInfo
    //
    len += vscf_asn1_writer_write_sequence(self->asn1_writer, len);

    //
    //  Finalize
    //
    VSCF_ASSERT(!vscf_asn1_writer_has_error(self->asn1_writer));

    return len;
}

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_pkcs8_serializer_serialized_public_key_len(const vscf_pkcs8_serializer_t *self,
        const vscf_raw_public_key_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));

    const vscf_impl_t *alg_info = vscf_raw_public_key_alg_info(public_key);
    const size_t alg_info_len = vscf_alg_info_der_serializer_serialized_len(self->alg_info_der_serializer, alg_info);
    const size_t wrapped_key_len = vscf_raw_public_key_data(public_key).len;
    const size_t len = 1 + 8 + //  SubjectPublicKeyInfo ::= SEQUENCE {
                       1 + 2 + alg_info_len + //          algorithm AlgorithmIdentifier,
                       1 + 8 + wrapped_key_len; //          subjectPublicKey BIT STRING
                                                //  }
    return len;
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs8_serializer_serialize_public_key(vscf_pkcs8_serializer_t *self, const vscf_raw_public_key_t *public_key,
        vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_raw_public_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs8_serializer_serialized_public_key_len(self, public_key));
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t len = vscf_pkcs8_serializer_serialize_public_key_inplace(self, public_key, &error);

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
vscf_pkcs8_serializer_serialized_private_key_len(const vscf_pkcs8_serializer_t *self,
        const vscf_raw_private_key_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));

    const vscf_impl_t *alg_info = vscf_raw_private_key_alg_info(private_key);
    const size_t alg_info_len = vscf_alg_info_der_serializer_serialized_len(self->alg_info_der_serializer, alg_info);
    const size_t wrapped_key_len = vscf_raw_private_key_data(private_key).len;
    const size_t len = 1 + 8 + //  PrivateKeyInfo ::= SEQUENCE {
                       1 + 1 + 1 + //          version Version,
                       1 + 2 + alg_info_len + //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
                       1 + 8 + wrapped_key_len + //          privateKey PrivateKey,
                       0; //          attributes [0] IMPLICIT Attributes OPTIONAL
                                                 //  }
    return len;
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_status_t
vscf_pkcs8_serializer_serialize_private_key(vscf_pkcs8_serializer_t *self, const vscf_raw_private_key_t *private_key,
        vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_raw_private_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_pkcs8_serializer_serialized_private_key_len(self, private_key));
    VSCF_ASSERT_PTR(self->asn1_writer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_asn1_writer_reset(self->asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t len = vscf_pkcs8_serializer_serialize_private_key_inplace(self, private_key, &error);

    if (vscf_error_has_error(&error)) {
        return vscf_error_status(&error);
    }

    vscf_asn1_writer_finish(self->asn1_writer, vsc_buffer_is_reverse(out));
    vsc_buffer_inc_used(out, len);

    return vscf_status_SUCCESS;
}
