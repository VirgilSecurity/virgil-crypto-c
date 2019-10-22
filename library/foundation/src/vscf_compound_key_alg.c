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
//  This module contains 'compound key alg' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_compound_key_alg.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_simple_alg_info.h"
#include "vscf_key_alg_factory.h"
#include "vscf_signer.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_key_cipher.h"
#include "vscf_key_signer.h"
#include "vscf_ctr_drbg.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_random.h"
#include "vscf_compound_key_alg_defs.h"
#include "vscf_compound_key_alg_internal.h"

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
//  Note, this method is called automatically when method vscf_compound_key_alg_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_compound_key_alg_init_ctx(vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    self->key_provider = vscf_key_provider_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_compound_key_alg_cleanup_ctx(vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_key_provider_destroy(&self->key_provider);
}

//
//  This method is called when interface 'random' was setup.
//
VSCF_PRIVATE void
vscf_compound_key_alg_did_setup_random(vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_provider);

    vscf_key_provider_release_random(self->key_provider);
    vscf_key_provider_use_random(self->key_provider, self->random);
}

//
//  This method is called when interface 'random' was released.
//
VSCF_PRIVATE void
vscf_compound_key_alg_did_release_random(vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_provider);

    vscf_key_provider_release_random(self->key_provider);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_compound_key_alg_setup_defaults(vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);

        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }

        vscf_compound_key_alg_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vscf_status_SUCCESS;
}

//
//  Generate new compound private key from given encryption algorithm
//  identifier and signing algorithm identifier.
//
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_generate_key(
        const vscf_compound_key_alg_t *self, vscf_alg_id_t enc_alg_id, vscf_alg_id_t sign_alg_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(enc_alg_id != vscf_alg_id_NONE);
    VSCF_ASSERT(sign_alg_id != vscf_alg_id_NONE);

    vscf_impl_t *enc_key = NULL;
    vscf_impl_t *enc_key_alg = NULL;
    vscf_impl_t *sign_key = NULL;
    vscf_impl_t *sign_key_alg = NULL;
    vscf_impl_t *alg_info = NULL;
    vscf_impl_t *private_key = NULL;
    vscf_impl_t *enc_key_public = NULL;
    vscf_raw_public_key_t *raw_enc_key_public = NULL;
    vscf_signer_t *signer = NULL;
    vsc_buffer_t *signature = NULL;
    vscf_status_t sign_status = vscf_status_SUCCESS;


    //
    //  Generate keys.
    //
    enc_key = vscf_key_provider_generate_private_key(self->key_provider, enc_alg_id, error);
    if (NULL == enc_key) {
        goto cleanup;
    }

    sign_key = vscf_key_provider_generate_private_key(self->key_provider, sign_alg_id, error);
    if (NULL == sign_key) {
        goto cleanup;
    }

    //
    //  Check algorithms.
    //
    enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, error);
    if (!vscf_key_cipher_is_implemented(enc_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    sign_key_alg = vscf_key_alg_factory_create_from_key(sign_key, self->random, error);
    if (!vscf_key_signer_is_implemented(sign_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    // Sign encryption public key.
    //
    enc_key_public = vscf_private_key_extract_public_key(enc_key);
    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(enc_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    raw_enc_key_public = vscf_key_alg_export_public_key(enc_key_alg, enc_key_public, error);
    if (NULL == raw_enc_key_public) {
        goto cleanup;
    }

    signer = vscf_signer_new();
    vscf_signer_use_random(signer, self->random);

    signature = vsc_buffer_new_with_capacity(vscf_signer_signature_len(signer, sign_key));
    vscf_signer_reset(signer);
    vscf_signer_append_data(signer, vscf_raw_public_key_data(raw_enc_key_public));
    sign_status = vscf_signer_sign(signer, sign_key, signature);

    if (sign_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, sign_status);
        goto cleanup;
    }

    alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos(
            vscf_alg_id_COMPOUND_KEY_ALG, vscf_key_alg_info(enc_key), vscf_key_alg_info(sign_key)));

    private_key = vscf_compound_private_key_impl(
            vscf_compound_private_key_new_with_members(alg_info, &enc_key, &sign_key, &signature));

cleanup:
    vsc_buffer_destroy(&signature);
    vscf_signer_destroy(&signer);
    vscf_raw_public_key_destroy(&raw_enc_key_public);
    vscf_impl_destroy(&enc_key_public);
    vscf_impl_destroy(&alg_info);
    vscf_impl_destroy(&sign_key_alg);
    vscf_impl_destroy(&sign_key);
    vscf_impl_destroy(&enc_key_alg);
    vscf_impl_destroy(&enc_key);

    return private_key;
}

//
//  Generate new compound private key with post-quantum algorithms.
//
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_generate_post_quantum_key(const vscf_compound_key_alg_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);

    return vscf_compound_key_alg_generate_key(self, vscf_alg_id_ROUND5, vscf_alg_id_FALCON, error);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_compound_key_alg_alg_id(const vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_COMPOUND_KEY_ALG;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_produce_alg_info(const vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    vscf_simple_alg_info_t *alg_info = vscf_simple_alg_info_new_with_alg_id(vscf_compound_key_alg_alg_id(self));
    return vscf_simple_alg_info_impl(alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_compound_key_alg_restore_alg_info(vscf_compound_key_alg_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_compound_key_alg_alg_id(self));

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_generate_ephemeral_key(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vscf_key_is_implemented(key));

    if (vscf_key_impl_tag(key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    const vscf_impl_tag_t impl_tag = vscf_impl_tag(key);
    vscf_alg_id_t enc_alg_id = vscf_alg_id_NONE;
    vscf_alg_id_t sign_alg_id = vscf_alg_id_NONE;
    if (impl_tag == vscf_impl_tag_COMPOUND_PUBLIC_KEY) {
        const vscf_compound_public_key_t *public_key = (const vscf_compound_public_key_t *)key;
        enc_alg_id = vscf_key_alg_id(vscf_compound_public_key_get_encryption_key(public_key));
        sign_alg_id = vscf_key_alg_id(vscf_compound_public_key_get_verifying_key(public_key));

    } else if (impl_tag == vscf_impl_tag_COMPOUND_PRIVATE_KEY) {
        const vscf_compound_private_key_t *private_key = (const vscf_compound_private_key_t *)key;
        enc_alg_id = vscf_key_alg_id(vscf_compound_private_key_get_decryption_key(private_key));
        sign_alg_id = vscf_key_alg_id(vscf_compound_private_key_get_signing_key(private_key));

    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    return vscf_compound_key_alg_generate_key(self, enc_alg_id, sign_alg_id, error);
}

//
//  Import public key from the raw binary format.
//
//  Return public key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be imported from the format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_import_public_key(
        const vscf_compound_key_alg_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_PTR(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Export public key to the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_public_key_t *
vscf_compound_key_alg_export_public_key(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    //
    //  Prepare keys.
    //
    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);
    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *encryption_key = vscf_compound_public_key_get_encryption_key(compound_public_key);
    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);
    const vsc_data_t signature = vscf_compound_public_key_get_encryption_key_signature(compound_public_key);

    //
    //  Prepare result variables.
    //
    vsc_buffer_t *raw_public_key_buf = vsc_buffer_new();
    vscf_raw_public_key_t *raw_public_key = NULL;
    vscf_raw_public_key_t *encryption_raw_public_key = NULL;
    vscf_raw_public_key_t *verifying_raw_public_key = NULL;
    vscf_asn1wr_t asn1wr;
    size_t raw_public_key_buf_len = 0;
    size_t raw_public_key_len = 0;

    //
    //  Create correspond algs.
    //
    vscf_impl_t *encryption_key_alg = vscf_key_alg_factory_create_from_key(encryption_key, self->random, error);
    VSCF_ASSERT_PTR(encryption_key_alg);
    vscf_impl_t *verifying_key_alg = vscf_key_alg_factory_create_from_key(verifying_key, self->random, error);
    VSCF_ASSERT_PTR(verifying_key_alg);
    vscf_impl_t *alg_info =
            (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_compound_public_key_alg_info(compound_public_key));

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(encryption_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(verifying_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Export.
    //
    encryption_raw_public_key = vscf_key_alg_export_public_key(encryption_key_alg, encryption_key, error);
    if (NULL == encryption_raw_public_key) {
        goto cleanup;
    }

    verifying_raw_public_key = vscf_key_alg_export_public_key(verifying_key_alg, verifying_key, error);
    if (NULL == verifying_raw_public_key) {
        goto cleanup;
    }

    //
    //  Write to the ASN.1 structure.
    //
    //  CompoundPublicKey ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      encKey OCTET STRING,
    //      verKey OCTET STRING,
    //      encKeySignature OCTET STRING
    //  }
    //
    //  version is the syntax version number. The appropriate value
    //  depends on encKeySignature. The version MUST 0 and denotes that
    //  encKeySignature handles VirgilSignature.

    raw_public_key_buf_len = 1 + 4 +                                                           //  CompoundPublicKey
                             1 + 1 + 1 +                                                       //      version
                             1 + 4 + vscf_raw_public_key_data(encryption_raw_public_key).len + //      encKey
                             1 + 4 + vscf_raw_public_key_data(verifying_raw_public_key).len +  //      verKey
                             1 + 4 + signature.len;                                            //      encKeySignature


    vsc_buffer_alloc(raw_public_key_buf, raw_public_key_buf_len);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(raw_public_key_buf), vsc_buffer_unused_len(raw_public_key_buf));

    //
    //  Write.
    //
    raw_public_key_len += vscf_asn1wr_write_octet_str(&asn1wr, signature);
    raw_public_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(verifying_raw_public_key));
    raw_public_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(encryption_raw_public_key));
    raw_public_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_public_key_len);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, false);
    vsc_buffer_inc_used(raw_public_key_buf, raw_public_key_len);

    raw_public_key = vscf_raw_public_key_new_with_buffer(&raw_public_key_buf, &alg_info);

cleanup:
    vscf_raw_public_key_destroy(&verifying_raw_public_key);
    vscf_raw_public_key_destroy(&encryption_raw_public_key);
    vsc_buffer_destroy(&raw_public_key_buf);
    vscf_impl_destroy(&alg_info);
    vscf_impl_destroy(&verifying_key_alg);
    vscf_impl_destroy(&encryption_key_alg);

    return raw_public_key;
}

//
//  Import private key from the raw binary format.
//
//  Return private key that is adopted and optimized to be used
//  with this particular algorithm.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_import_private_key(
        const vscf_compound_key_alg_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_PTR(error);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_private_key_t *
vscf_compound_key_alg_export_private_key(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    //
    //  Prepare keys.
    //
    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);
    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *decryption_key = vscf_compound_private_key_get_decryption_key(compound_private_key);
    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);

    //
    //  Prepare result variables.
    //
    vsc_buffer_t *raw_private_key_buf = vsc_buffer_new();
    vscf_raw_private_key_t *raw_private_key = NULL;
    vscf_raw_private_key_t *decryption_raw_private_key = NULL;
    vscf_raw_private_key_t *signing_raw_private_key = NULL;
    vscf_asn1wr_t asn1wr;
    size_t raw_private_key_buf_len = 0;
    size_t raw_private_key_len = 0;

    //
    //  Create correspond algs.
    //
    vscf_impl_t *decryption_key_alg = vscf_key_alg_factory_create_from_key(decryption_key, self->random, error);
    VSCF_ASSERT_PTR(decryption_key_alg);
    vscf_impl_t *signing_key_alg = vscf_key_alg_factory_create_from_key(signing_key, self->random, error);
    VSCF_ASSERT_PTR(signing_key_alg);
    vscf_impl_t *alg_info =
            (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_compound_private_key_alg_info(compound_private_key));

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(decryption_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(signing_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Export.
    //
    decryption_raw_private_key = vscf_key_alg_export_private_key(decryption_key_alg, decryption_key, error);
    if (NULL == decryption_raw_private_key) {
        goto cleanup;
    }

    signing_raw_private_key = vscf_key_alg_export_private_key(signing_key_alg, signing_key, error);
    if (NULL == signing_raw_private_key) {
        goto cleanup;
    }

    //
    //  Write to the ASN.1 structure.
    //
    //  CompoundPrivateKey ::= SEQUENCE {
    //      version INTEGER { v0(0) } DEFAULT v0,
    //      decKey OCTET STRING,
    //      sigKey OCTET STRING
    //  }
    //
    //  version is the syntax version number. The appropriate value
    //  depends on a signature algorithm. The version MUST be 0
    //  and denotes that calculated signature is VirgilSignature.

    raw_private_key_buf_len = 1 + 4 +                                                             //  CompoundPublicKey
                              1 + 1 + 1 +                                                         //      version
                              1 + 4 + vscf_raw_private_key_data(decryption_raw_private_key).len + //      decKey
                              1 + 4 + vscf_raw_private_key_data(signing_raw_private_key).len;     //      sigKey


    vsc_buffer_alloc(raw_private_key_buf, raw_private_key_buf_len);
    vscf_asn1wr_reset(
            &asn1wr, vsc_buffer_unused_bytes(raw_private_key_buf), vsc_buffer_unused_len(raw_private_key_buf));

    //
    //  Write.
    //
    raw_private_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(signing_raw_private_key));
    raw_private_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(decryption_raw_private_key));
    raw_private_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_private_key_len);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, false);
    vsc_buffer_inc_used(raw_private_key_buf, raw_private_key_len);

    raw_private_key = vscf_raw_private_key_new_with_buffer(&raw_private_key_buf, &alg_info);

cleanup:
    vscf_raw_private_key_destroy(&signing_raw_private_key);
    vscf_raw_private_key_destroy(&decryption_raw_private_key);
    vsc_buffer_destroy(&raw_private_key_buf);
    vscf_impl_destroy(&alg_info);
    vscf_impl_destroy(&signing_key_alg);
    vscf_impl_destroy(&decryption_key_alg);

    return raw_private_key;
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_can_encrypt(const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *enc_key = vscf_compound_public_key_get_encryption_key(compound_public_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const bool can_encrypt = vscf_key_cipher_can_encrypt(enc_key_alg, enc_key, data_len);
    vscf_impl_destroy(&enc_key_alg);
    return can_encrypt;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_compound_key_alg_encrypted_len(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *enc_key = vscf_compound_public_key_get_encryption_key(compound_public_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const size_t encrypted_len = vscf_key_cipher_encrypted_len(enc_key_alg, enc_key, data_len);
    vscf_impl_destroy(&enc_key_alg);
    return encrypted_len;
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_compound_key_alg_encrypt(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_compound_key_alg_can_encrypt(self, public_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_compound_key_alg_encrypted_len(self, public_key, data.len));

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *enc_key = vscf_compound_public_key_get_encryption_key(compound_public_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const vscf_status_t status = vscf_key_cipher_encrypt(enc_key_alg, enc_key, data, out);
    vscf_impl_destroy(&enc_key_alg);
    return status;
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_can_decrypt(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *enc_key = vscf_compound_private_key_get_decryption_key(compound_private_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const bool can_decrypt = vscf_key_cipher_can_decrypt(enc_key_alg, enc_key, data_len);
    vscf_impl_destroy(&enc_key_alg);
    return can_decrypt;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_compound_key_alg_decrypted_len(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *enc_key = vscf_compound_private_key_get_decryption_key(compound_private_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const size_t decrypted_len = vscf_key_cipher_decrypted_len(enc_key_alg, enc_key, data_len);
    vscf_impl_destroy(&enc_key_alg);
    return decrypted_len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_compound_key_alg_decrypt(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_compound_key_alg_can_decrypt(self, private_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_compound_key_alg_decrypted_len(self, private_key, data.len));

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *enc_key = vscf_compound_private_key_get_decryption_key(compound_private_key);

    vscf_impl_t *enc_key_alg = vscf_key_alg_factory_create_from_key(enc_key, self->random, NULL);
    VSCF_ASSERT_PTR(enc_key_alg);

    const vscf_status_t status = vscf_key_cipher_decrypt(enc_key_alg, enc_key, data, out);
    vscf_impl_destroy(&enc_key_alg);
    return status;
}

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_can_sign(const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);

    vscf_impl_t *signing_key_alg = vscf_key_alg_factory_create_from_key(signing_key, self->random, NULL);
    VSCF_ASSERT_PTR(signing_key_alg);

    const bool can_sign = vscf_key_signer_can_sign(signing_key_alg, signing_key);
    vscf_impl_destroy(&signing_key_alg);
    return can_sign;
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_compound_key_alg_signature_len(const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);

    vscf_impl_t *signing_key_alg = vscf_key_alg_factory_create_from_key(signing_key, self->random, NULL);
    VSCF_ASSERT_PTR(signing_key_alg);

    const size_t signature_len = vscf_key_signer_signature_len(signing_key_alg, signing_key);
    vscf_impl_destroy(&signing_key_alg);
    return signature_len;
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_compound_key_alg_sign_hash(const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key,
        vscf_alg_id_t hash_id, vsc_data_t digest, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_compound_key_alg_can_sign(self, private_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_compound_key_alg_signature_len(self, private_key));

    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;
    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);

    vscf_impl_t *signing_key_alg = vscf_key_alg_factory_create_from_key(signing_key, self->random, NULL);
    VSCF_ASSERT_PTR(signing_key_alg);

    const vscf_status_t status = vscf_key_signer_sign_hash(signing_key_alg, signing_key, hash_id, digest, signature);
    vscf_impl_destroy(&signing_key_alg);
    return status;
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_can_verify(const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);

    vscf_impl_t *verifying_key_alg = vscf_key_alg_factory_create_from_key(verifying_key, self->random, NULL);
    VSCF_ASSERT_PTR(verifying_key_alg);

    const bool can_verify = vscf_key_signer_can_verify(verifying_key_alg, verifying_key);
    vscf_impl_destroy(&verifying_key_alg);
    return can_verify;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_verify_hash(const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key,
        vscf_alg_id_t hash_id, vsc_data_t digest, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_compound_key_alg_can_verify(self, public_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);

    vscf_impl_t *verifying_key_alg = vscf_key_alg_factory_create_from_key(verifying_key, self->random, NULL);
    VSCF_ASSERT_PTR(verifying_key_alg);

    const vscf_status_t status =
            vscf_key_signer_verify_hash(verifying_key_alg, verifying_key, hash_id, digest, signature);
    vscf_impl_destroy(&verifying_key_alg);
    return status;
}
