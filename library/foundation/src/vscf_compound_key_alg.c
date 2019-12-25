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
#include "vscf_alg_factory.h"
#include "vscf_key_alg_factory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_key_cipher.h"
#include "vscf_key_signer.h"
#include "vscf_ctr_drbg.h"
#include "vscf_sha512.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1rd_defs.h"
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
//  Make compound private key from given.
//
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_compound_key_alg_make_key(const vscf_compound_key_alg_t *self, const vscf_impl_t *cipher_key,
        const vscf_impl_t *signer_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT(vscf_private_key_is_implemented(cipher_key));
    VSCF_ASSERT(vscf_private_key_is_implemented(signer_key));

    vscf_impl_t *cipher_key_alg = NULL;
    vscf_impl_t *signer_key_alg = NULL;
    vscf_impl_t *alg_info = NULL;
    vscf_impl_t *private_key = NULL;

    //
    //  Check algorithms.
    //
    cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, error);

    if (NULL == cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, error);

    if (NULL == signer_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_signer_is_implemented(signer_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos(
            vscf_alg_id_COMPOUND_KEY, vscf_key_alg_info(cipher_key), vscf_key_alg_info(signer_key)));

    private_key =
            vscf_compound_private_key_impl(vscf_compound_private_key_new_with_keys(&alg_info, cipher_key, signer_key));

cleanup:
    vscf_impl_destroy(&signer_key_alg);
    vscf_impl_destroy(&cipher_key_alg);

    return private_key;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_compound_key_alg_alg_id(const vscf_compound_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_COMPOUND_KEY;
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

    //
    //  Get underlying keys.
    //
    const vscf_impl_tag_t impl_tag = vscf_impl_tag(key);
    const vscf_impl_t *cipher_key = NULL;
    const vscf_impl_t *signer_key = NULL;
    if (impl_tag == vscf_impl_tag_COMPOUND_PUBLIC_KEY) {
        const vscf_compound_public_key_t *public_key = (const vscf_compound_public_key_t *)key;
        cipher_key = vscf_compound_public_key_cipher_key(public_key);
        signer_key = vscf_compound_public_key_signer_key(public_key);

    } else if (impl_tag == vscf_impl_tag_COMPOUND_PRIVATE_KEY) {
        const vscf_compound_private_key_t *private_key = (const vscf_compound_private_key_t *)key;
        cipher_key = vscf_compound_private_key_cipher_key(private_key);
        signer_key = vscf_compound_private_key_signer_key(private_key);

    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    //
    //  Generate ephemeral underlying keys.
    //
    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, error);
    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, error);

    VSCF_ASSERT_PTR(cipher_key_alg);
    VSCF_ASSERT_PTR(signer_key_alg);
    VSCF_ASSERT(vscf_key_cipher_is_implemented(cipher_key_alg));
    VSCF_ASSERT(vscf_key_signer_is_implemented(signer_key_alg));

    vscf_impl_t *ephemeral_key = NULL;
    vscf_impl_t *ephemeral_cipher_key = NULL;
    vscf_impl_t *ephemeral_signer_key = NULL;

    ephemeral_cipher_key = vscf_key_alg_generate_ephemeral_key(cipher_key_alg, cipher_key, error);
    if (NULL == ephemeral_cipher_key) {
        goto cleanup;
    }

    ephemeral_signer_key = vscf_key_alg_generate_ephemeral_key(signer_key_alg, signer_key, error);
    if (NULL == ephemeral_signer_key) {
        goto cleanup;
    }

    ephemeral_key = vscf_compound_key_alg_make_key(self, ephemeral_cipher_key, ephemeral_signer_key, error);

cleanup:
    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&signer_key_alg);
    vscf_impl_destroy(&ephemeral_cipher_key);
    vscf_impl_destroy(&ephemeral_signer_key);

    return ephemeral_key;
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
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    return vscf_compound_key_alg_import_public_key_data(
            self, vscf_raw_public_key_data(raw_key), vscf_raw_public_key_alg_info(raw_key), error);
}

//
//  Import public key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_compound_key_alg_import_public_key_data(const vscf_compound_key_alg_t *self, vsc_data_t key_data,
        const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    //
    //  Check if raw key is appropriate.
    //
    if (vscf_impl_tag(key_alg_info) != vscf_impl_tag_COMPOUND_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(key_alg_info) == vscf_alg_id_COMPOUND_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // CompoundPublicKey ::= SEQUENCE {
    //     cipherKey OCTET STRING,
    //     signerKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, key_data);
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t signer_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_COMPOUND_PUBLIC_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_compound_key_alg_info_t *compound_alg_info = (const vscf_compound_key_alg_info_t *)key_alg_info;
    const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_alg_info);
    const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_alg_info);

    vscf_impl_t *cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(cipher_alg_info);
    vscf_raw_public_key_t *raw_cipher_key = vscf_raw_public_key_new_with_data(cipher_key_data, &cipher_alg_info_copy);

    vscf_impl_t *signer_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(signer_alg_info);
    vscf_raw_public_key_t *raw_signer_key = vscf_raw_public_key_new_with_data(signer_key_data, &signer_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *cipher_key_alg = NULL;
    vscf_impl_t *cipher_key = NULL;
    vscf_impl_t *signer_key_alg = NULL;
    vscf_impl_t *signer_key = NULL;
    vscf_impl_t *public_key = NULL;

    //
    //  Get correspond algs.
    //
    cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(cipher_alg_info), self->random, error);

    if (NULL == cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    signer_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(signer_alg_info), self->random, error);

    if (NULL == signer_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_signer_is_implemented(signer_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    cipher_key = vscf_key_alg_import_public_key(cipher_key_alg, raw_cipher_key, error);
    if (NULL == cipher_key) {
        goto cleanup;
    }

    signer_key = vscf_key_alg_import_public_key(signer_key_alg, raw_signer_key, error);
    if (NULL == signer_key) {
        goto cleanup;
    }

    //
    //  Make compound key.
    //
    public_key = vscf_compound_public_key_impl(
            vscf_compound_public_key_new_with_keys_disown(key_alg_info, &cipher_key, &signer_key));

cleanup:
    vscf_raw_public_key_destroy(&raw_cipher_key);
    vscf_raw_public_key_destroy(&raw_signer_key);
    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&cipher_key);
    vscf_impl_destroy(&signer_key_alg);
    vscf_impl_destroy(&signer_key);

    return public_key;
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

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);

    //
    //  Export key data.
    //
    const size_t raw_key_buf_size = vscf_compound_key_alg_exported_public_key_data_len(self, public_key);
    vsc_buffer_t *raw_key_buf = vsc_buffer_new_with_capacity(raw_key_buf_size);

    const vscf_status_t export_status = vscf_compound_key_alg_export_public_key_data(self, public_key, raw_key_buf);
    if (export_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, export_status);
        return NULL;
    }

    //
    //  Export key alg info.
    //
    vscf_impl_t *alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_key_alg_info(public_key));
    vscf_raw_public_key_t *raw_key = vscf_raw_public_key_new_with_buffer(&raw_key_buf, &alg_info);

    return raw_key;
}

//
//  Return length in bytes required to hold exported public key.
//
VSCF_PRIVATE size_t
vscf_compound_key_alg_exported_public_key_data_len(const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return 0;
    }

    //
    //  Get correspond key algorithms.
    //
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);
    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *cipher_key = vscf_compound_public_key_cipher_key(compound_public_key);
    const vscf_impl_t *signer_key = vscf_compound_public_key_signer_key(compound_public_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const size_t cipher_data_key_len = vscf_key_alg_exported_public_key_data_len(cipher_key_alg, cipher_key);
    const size_t signer_data_key_len = vscf_key_alg_exported_public_key_data_len(signer_key_alg, signer_key);

    const size_t key_data_len = 1 + 4 +                       // CompoundPublicKey ::= SEQUENCE {
                                1 + 4 + cipher_data_key_len + //     cipherKey OCTET STRING,
                                1 + 4 + signer_data_key_len;  //     signerKey OCTET STRING }

    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&signer_key_alg);

    return key_data_len;
}

//
//  Export public key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PRIVATE vscf_status_t
vscf_compound_key_alg_export_public_key_data(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    //
    // Write to the ASN.1 structure.
    //
    // CompoundPublicKey ::= SEQUENCE {
    //     cipherKey OCTET STRING,
    //     signerKey OCTET STRING
    // }
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_compound_key_alg_exported_public_key_data_len(self, public_key));

    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_COMPOUND_PUBLIC_KEY);
    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *cipher_key = vscf_compound_public_key_cipher_key(compound_public_key);
    const vscf_impl_t *signer_key = vscf_compound_public_key_signer_key(compound_public_key);

    //
    //  Get correspond key algorithms.
    //
    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, &error);
    VSCF_ASSERT_PTR(cipher_key_alg);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, &error);
    VSCF_ASSERT_PTR(signer_key_alg);

    vscf_raw_public_key_t *raw_cipher_key = NULL;
    vscf_raw_public_key_t *raw_signer_key = NULL;

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(cipher_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(signer_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //  TODO: Optimize memcpy by writing directly to the out.
    raw_cipher_key = vscf_key_alg_export_public_key(cipher_key_alg, cipher_key, &error);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    raw_signer_key = vscf_key_alg_export_public_key(signer_key_alg, signer_key, &error);
    if (NULL == raw_signer_key) {
        goto cleanup;
    }

    //
    //  Write.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t raw_key_len = 0;
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_signer_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_cipher_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(out));
    vscf_asn1wr_cleanup(&asn1wr);

    vsc_buffer_inc_used(out, raw_key_len);

cleanup:
    vscf_raw_public_key_destroy(&raw_cipher_key);
    vscf_raw_public_key_destroy(&raw_signer_key);
    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&signer_key_alg);

    return vscf_error_status(&error);
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
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    return vscf_compound_key_alg_import_private_key_data(
            self, vscf_raw_private_key_data(raw_key), vscf_raw_private_key_alg_info(raw_key), error);
}

//
//  Import private key from the raw binary format.
//
VSCF_PRIVATE vscf_impl_t *
vscf_compound_key_alg_import_private_key_data(const vscf_compound_key_alg_t *self, vsc_data_t key_data,
        const vscf_impl_t *key_alg_info, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key_data));
    VSCF_ASSERT_PTR(key_alg_info);

    //
    //  Check if raw key is appropriate.
    //
    if (vscf_impl_tag(key_alg_info) != vscf_impl_tag_COMPOUND_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(key_alg_info) == vscf_alg_id_COMPOUND_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // CompoundPrivateKey ::= SEQUENCE {
    //     cipherKey OCTET STRING,
    //     signerKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, key_data);
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t signer_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_COMPOUND_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_compound_key_alg_info_t *compound_alg_info = (const vscf_compound_key_alg_info_t *)key_alg_info;
    const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_alg_info);
    const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_alg_info);

    vscf_impl_t *cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(cipher_alg_info);
    vscf_raw_private_key_t *raw_cipher_key = vscf_raw_private_key_new_with_data(cipher_key_data, &cipher_alg_info_copy);

    vscf_impl_t *signer_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(signer_alg_info);
    vscf_raw_private_key_t *raw_signer_key = vscf_raw_private_key_new_with_data(signer_key_data, &signer_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *cipher_key_alg = NULL;
    vscf_impl_t *cipher_key = NULL;
    vscf_impl_t *signer_key_alg = NULL;
    vscf_impl_t *signer_key = NULL;
    vscf_impl_t *private_key = NULL;

    //
    //  Get correspond algs.
    //
    cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(cipher_alg_info), self->random, error);

    if (NULL == cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    signer_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(signer_alg_info), self->random, error);

    if (NULL == signer_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_signer_is_implemented(signer_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    cipher_key = vscf_key_alg_import_private_key(cipher_key_alg, raw_cipher_key, error);
    if (NULL == cipher_key) {
        goto cleanup;
    }

    signer_key = vscf_key_alg_import_private_key(signer_key_alg, raw_signer_key, error);
    if (NULL == signer_key) {
        goto cleanup;
    }

    //
    //  Make compound key.
    //
    private_key = vscf_compound_private_key_impl(
            vscf_compound_private_key_new_with_keys_disown(key_alg_info, &cipher_key, &signer_key));

cleanup:
    vscf_raw_private_key_destroy(&raw_cipher_key);
    vscf_raw_private_key_destroy(&raw_signer_key);
    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&cipher_key);
    vscf_impl_destroy(&signer_key_alg);
    vscf_impl_destroy(&signer_key);

    return private_key;
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

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);

    const size_t raw_key_buf_size = vscf_compound_key_alg_exported_private_key_data_len(self, private_key);
    vsc_buffer_t *raw_key_buf = vsc_buffer_new_with_capacity(raw_key_buf_size);

    const vscf_status_t export_status = vscf_compound_key_alg_export_private_key_data(self, private_key, raw_key_buf);

    if (export_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, export_status);
        return NULL;
    }

    vscf_impl_t *alg_info = (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_key_alg_info(private_key));
    vscf_raw_private_key_t *raw_key = vscf_raw_private_key_new_with_buffer(&raw_key_buf, &alg_info);

    return raw_key;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PRIVATE size_t
vscf_compound_key_alg_exported_private_key_data_len(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return 0;
    }

    //
    //  Get correspond key algorithms.
    //
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);
    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *cipher_key = vscf_compound_private_key_cipher_key(compound_private_key);
    const vscf_impl_t *signer_key = vscf_compound_private_key_signer_key(compound_private_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const size_t cipher_data_key_len = vscf_key_alg_exported_private_key_data_len(cipher_key_alg, cipher_key);
    const size_t signer_data_key_len = vscf_key_alg_exported_private_key_data_len(signer_key_alg, signer_key);

    const size_t key_data_len = 1 + 4 +                       // CompoundPrivateKey ::= SEQUENCE {
                                1 + 4 + cipher_data_key_len + //     cipherKey OCTET STRING,
                                1 + 4 + signer_data_key_len;  //     signerKey OCTET STRING }

    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&signer_key_alg);

    return key_data_len;
}

//
//  Export private key to the raw binary format without algorithm information.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PRIVATE vscf_status_t
vscf_compound_key_alg_export_private_key_data(
        const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    //
    // Write to the ASN.1 structure.
    //
    // CompoundPrivateKey ::= SEQUENCE {
    //     cipherKey OCTET STRING,
    //     signerKey OCTET STRING
    // }
    //

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_compound_key_alg_exported_private_key_data_len(self, private_key));

    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        return vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM;
    }

    vscf_error_t error;
    vscf_error_reset(&error);

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_COMPOUND_PRIVATE_KEY);
    const vscf_compound_private_key_t *compound_private_key = (const vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *cipher_key = vscf_compound_private_key_cipher_key(compound_private_key);
    const vscf_impl_t *signer_key = vscf_compound_private_key_signer_key(compound_private_key);

    //
    //  Get correspond key algorithms.
    //
    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, &error);
    VSCF_ASSERT_PTR(cipher_key_alg);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, &error);
    VSCF_ASSERT_PTR(signer_key_alg);

    vscf_raw_private_key_t *raw_cipher_key = NULL;
    vscf_raw_private_key_t *raw_signer_key = NULL;

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(cipher_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(signer_key_alg))) {
        vscf_error_update(&error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //  TODO: Optimize memcpy by writing directly to the out.
    raw_cipher_key = vscf_key_alg_export_private_key(cipher_key_alg, cipher_key, &error);
    if (vscf_error_has_error(&error)) {
        goto cleanup;
    }

    raw_signer_key = vscf_key_alg_export_private_key(signer_key_alg, signer_key, &error);
    if (NULL == raw_signer_key) {
        goto cleanup;
    }

    //
    //  Write.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t raw_key_len = 0;
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_signer_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_cipher_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);

    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));
    vscf_asn1wr_finish(&asn1wr, vsc_buffer_is_reverse(out));
    vscf_asn1wr_cleanup(&asn1wr);

    vsc_buffer_inc_used(out, raw_key_len);

cleanup:
    vscf_raw_private_key_destroy(&raw_cipher_key);
    vscf_raw_private_key_destroy(&raw_signer_key);
    vscf_impl_destroy(&cipher_key_alg);
    vscf_impl_destroy(&signer_key_alg);

    return vscf_error_status(&error);
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
    const vscf_impl_t *cipher_key = vscf_compound_public_key_cipher_key(compound_public_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const bool can_encrypt = vscf_key_cipher_can_encrypt(cipher_key_alg, cipher_key, data_len);
    vscf_impl_destroy(&cipher_key_alg);
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
    const vscf_impl_t *cipher_key = vscf_compound_public_key_cipher_key(compound_public_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const size_t encrypted_len = vscf_key_cipher_encrypted_len(cipher_key_alg, cipher_key, data_len);
    vscf_impl_destroy(&cipher_key_alg);

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
    const vscf_impl_t *cipher_key = vscf_compound_public_key_cipher_key(compound_public_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const vscf_status_t status = vscf_key_cipher_encrypt(cipher_key_alg, cipher_key, data, out);
    vscf_impl_destroy(&cipher_key_alg);
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
    const vscf_impl_t *cipher_key = vscf_compound_private_key_cipher_key(compound_private_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const bool can_decrypt = vscf_key_cipher_can_decrypt(cipher_key_alg, cipher_key, data_len);
    vscf_impl_destroy(&cipher_key_alg);
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
    const vscf_impl_t *cipher_key = vscf_compound_private_key_cipher_key(compound_private_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const size_t decrypted_len = vscf_key_cipher_decrypted_len(cipher_key_alg, cipher_key, data_len);
    vscf_impl_destroy(&cipher_key_alg);
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
    const vscf_impl_t *cipher_key = vscf_compound_private_key_cipher_key(compound_private_key);

    vscf_impl_t *cipher_key_alg = vscf_key_alg_factory_create_from_key(cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(cipher_key_alg);

    const vscf_status_t status = vscf_key_cipher_decrypt(cipher_key_alg, cipher_key, data, out);
    vscf_impl_destroy(&cipher_key_alg);
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
    const vscf_impl_t *signer_key = vscf_compound_private_key_signer_key(compound_private_key);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const bool can_sign = vscf_key_signer_can_sign(signer_key_alg, signer_key);
    vscf_impl_destroy(&signer_key_alg);
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
    const vscf_impl_t *signer_key = vscf_compound_private_key_signer_key(compound_private_key);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const size_t signature_len = vscf_key_signer_signature_len(signer_key_alg, signer_key);
    vscf_impl_destroy(&signer_key_alg);
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
    const vscf_impl_t *signer_key = vscf_compound_private_key_signer_key(compound_private_key);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const vscf_status_t status = vscf_key_signer_sign_hash(signer_key_alg, signer_key, hash_id, digest, signature);
    vscf_impl_destroy(&signer_key_alg);
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
    const vscf_impl_t *signer_key = vscf_compound_public_key_signer_key(compound_public_key);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const bool can_verify = vscf_key_signer_can_verify(signer_key_alg, signer_key);
    vscf_impl_destroy(&signer_key_alg);
    return can_verify;
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_compound_key_alg_verify_hash(const vscf_compound_key_alg_t *self, const vscf_impl_t *public_key,
        vscf_alg_id_t hash_id, vsc_data_t digest, vsc_data_t signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_compound_key_alg_can_verify(self, public_key));
    VSCF_ASSERT(hash_id != vscf_alg_id_NONE);
    VSCF_ASSERT(vsc_data_is_valid(digest));
    VSCF_ASSERT(vsc_data_is_valid(signature));

    const vscf_compound_public_key_t *compound_public_key = (const vscf_compound_public_key_t *)public_key;
    const vscf_impl_t *signer_key = vscf_compound_public_key_signer_key(compound_public_key);

    vscf_impl_t *signer_key_alg = vscf_key_alg_factory_create_from_key(signer_key, self->random, NULL);
    VSCF_ASSERT_PTR(signer_key_alg);

    const vscf_status_t status = vscf_key_signer_verify_hash(signer_key_alg, signer_key, hash_id, digest, signature);
    vscf_impl_destroy(&signer_key_alg);
    return status;
}
