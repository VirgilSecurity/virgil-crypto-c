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
//  This module contains 'chained key alg' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_chained_key_alg.h"
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
#include "vscf_chained_public_key.h"
#include "vscf_chained_private_key.h"
#include "vscf_chained_key_alg_info.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1rd_defs.h"
#include "vscf_asn1wr_defs.h"
#include "vscf_random.h"
#include "vscf_chained_key_alg_defs.h"
#include "vscf_chained_key_alg_internal.h"

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
vscf_chained_key_alg_setup_defaults(vscf_chained_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);

        if (status != vscf_status_SUCCESS) {
            vscf_ctr_drbg_destroy(&random);
            return status;
        }

        vscf_chained_key_alg_take_random(self, vscf_ctr_drbg_impl(random));
    }

    return vscf_status_SUCCESS;
}

//
//  Make chained private key from given.
//
//  Note, l2 cipher should be able to encrypt data produced by the l1 cipher.
//
VSCF_PUBLIC vscf_impl_t *
vscf_chained_key_alg_make_key(const vscf_chained_key_alg_t *self, const vscf_impl_t *l1_cipher_key,
        const vscf_impl_t *l2_cipher_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(l1_cipher_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(l1_cipher_key));
    VSCF_ASSERT_PTR(l2_cipher_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(l2_cipher_key));

    //
    //  Check algorithms.
    //
    vscf_impl_t *key = NULL;
    vscf_impl_t *alg_info = NULL;
    vscf_impl_t *l1_cipher_key_alg = NULL;
    vscf_impl_t *l2_cipher_key_alg = NULL;

    l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, NULL, error);

    if (NULL == l1_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l1_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, NULL, error);

    if (NULL == l2_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l2_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos(
            vscf_alg_id_CHAINED_KEY, vscf_key_alg_info(l1_cipher_key), vscf_key_alg_info(l2_cipher_key)));
    key = vscf_chained_private_key_impl(
            vscf_chained_private_key_new_with_keys(&alg_info, l1_cipher_key, l2_cipher_key));

cleanup:
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);
    return key;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_chained_key_alg_alg_id(const vscf_chained_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_CHAINED_KEY;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_chained_key_alg_produce_alg_info(const vscf_chained_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_simple_alg_info_t *alg_info = vscf_simple_alg_info_new_with_alg_id(vscf_chained_key_alg_alg_id(self));
    return vscf_simple_alg_info_impl(alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_chained_key_alg_restore_alg_info(vscf_chained_key_alg_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_chained_key_alg_alg_id(self));

    return vscf_status_SUCCESS;
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_chained_key_alg_generate_ephemeral_key(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
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
    const vscf_impl_t *l1_cipher_key = NULL;
    const vscf_impl_t *l2_cipher_key = NULL;
    if (impl_tag == vscf_impl_tag_CHAINED_PUBLIC_KEY) {
        const vscf_chained_public_key_t *public_key = (const vscf_chained_public_key_t *)key;
        l1_cipher_key = vscf_chained_public_key_l1_cipher_key(public_key);
        l2_cipher_key = vscf_chained_public_key_l2_cipher_key(public_key);

    } else if (impl_tag == vscf_impl_tag_CHAINED_PRIVATE_KEY) {
        const vscf_chained_private_key_t *private_key = (const vscf_chained_private_key_t *)key;
        l1_cipher_key = vscf_chained_private_key_l1_cipher_key(private_key);
        l2_cipher_key = vscf_chained_private_key_l2_cipher_key(private_key);

    } else {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }

    //
    //  Generate ephemeral underlying keys.
    //
    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, error);
    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, error);

    VSCF_ASSERT_PTR(l1_cipher_key_alg);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);
    VSCF_ASSERT(vscf_key_cipher_is_implemented(l1_cipher_key_alg));
    VSCF_ASSERT(vscf_key_cipher_is_implemented(l2_cipher_key_alg));

    vscf_impl_t *ephemeral_key = NULL;
    vscf_impl_t *l1_ephemeral_cipher_key = NULL;
    vscf_impl_t *l2_ephemeral_cipher_key = NULL;


    l1_ephemeral_cipher_key = vscf_key_alg_generate_ephemeral_key(l1_cipher_key_alg, l1_cipher_key, error);
    if (NULL == l1_ephemeral_cipher_key) {
        goto cleanup;
    }

    l2_ephemeral_cipher_key = vscf_key_alg_generate_ephemeral_key(l2_cipher_key_alg, l2_cipher_key, error);
    if (NULL == l2_ephemeral_cipher_key) {
        goto cleanup;
    }

    ephemeral_key = vscf_chained_key_alg_make_key(self, l1_ephemeral_cipher_key, l2_ephemeral_cipher_key, error);

cleanup:
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);
    vscf_impl_destroy(&l1_ephemeral_cipher_key);
    vscf_impl_destroy(&l2_ephemeral_cipher_key);

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
vscf_chained_key_alg_import_public_key(
        const vscf_chained_key_alg_t *self, const vscf_raw_public_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_public_key_is_valid(raw_key));

    //
    //  Check if raw key is appropriate.
    //
    const vscf_impl_t *alg_info = vscf_raw_public_key_alg_info(raw_key);
    if (vscf_impl_tag(alg_info) != vscf_impl_tag_CHAINED_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_CHAINED_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // ChainedPublicKey ::= SEQUENCE {
    //     l1CipherKey OCTET STRING,
    //     l2CipherKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, vscf_raw_public_key_data(raw_key));
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t l1_cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t l2_cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_CHAINED_PUBLIC_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_chained_key_alg_info_t *chained_key_alg_info = (const vscf_chained_key_alg_info_t *)alg_info;
    const vscf_impl_t *l1_cipher_alg_info = vscf_chained_key_alg_info_l1_cipher_alg_info(chained_key_alg_info);
    const vscf_impl_t *l2_cipher_alg_info = vscf_chained_key_alg_info_l2_cipher_alg_info(chained_key_alg_info);

    vscf_impl_t *l1_cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(l1_cipher_alg_info);
    vscf_raw_public_key_t *raw_l1_cipher_key =
            vscf_raw_public_key_new_with_data(l1_cipher_key_data, &l1_cipher_alg_info_copy);

    vscf_impl_t *l2_cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(l2_cipher_alg_info);
    vscf_raw_public_key_t *raw_l2_cipher_key =
            vscf_raw_public_key_new_with_data(l2_cipher_key_data, &l2_cipher_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *l1_cipher_key_alg = NULL;
    vscf_impl_t *l1_cipher_key = NULL;
    vscf_impl_t *l2_cipher_key_alg = NULL;
    vscf_impl_t *l2_cipher_key = NULL;
    vscf_impl_t *public_key = NULL;

    //
    //  Get correspond algs.
    //
    l1_cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(l1_cipher_alg_info), self->random, error);

    if (NULL == l1_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l1_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    l2_cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(l2_cipher_alg_info), self->random, error);

    if (NULL == l2_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l2_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    l1_cipher_key = vscf_key_alg_import_public_key(l1_cipher_key_alg, raw_l1_cipher_key, error);
    if (NULL == l1_cipher_key) {
        goto cleanup;
    }

    l2_cipher_key = vscf_key_alg_import_public_key(l2_cipher_key_alg, raw_l2_cipher_key, error);
    if (NULL == l2_cipher_key) {
        goto cleanup;
    }

    //
    //  Make chained key.
    //
    public_key = vscf_chained_public_key_impl(
            vscf_chained_public_key_new_with_imported_keys(alg_info, &l1_cipher_key, &l2_cipher_key));

cleanup:
    vscf_raw_public_key_destroy(&raw_l1_cipher_key);
    vscf_raw_public_key_destroy(&raw_l2_cipher_key);
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l1_cipher_key);
    vscf_impl_destroy(&l2_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key);

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
vscf_chained_key_alg_export_public_key(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    //
    //  Prepare keys.
    //
    if (vscf_key_impl_tag(public_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_CHAINED_PUBLIC_KEY);
    const vscf_chained_public_key_t *chained_public_key = (const vscf_chained_public_key_t *)public_key;

    const vscf_impl_t *l1_cipher_key = vscf_chained_public_key_l1_cipher_key(chained_public_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_public_key_l2_cipher_key(chained_public_key);

    //
    //  Prepare result variables.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);

    vsc_buffer_t *raw_key_buf = vsc_buffer_new();
    size_t raw_key_buf_len = 0;

    vscf_raw_public_key_t *raw_key = NULL;
    size_t raw_key_len = 0;

    vscf_raw_public_key_t *raw_l1_cipher_key = NULL;
    size_t raw_l1_cipher_key_len = 0;

    vscf_raw_public_key_t *raw_l2_cipher_key = NULL;
    size_t raw_l2_cipher_key_len = 0;

    //
    //  Create correspond algs.
    //
    vscf_impl_t *alg_info =
            (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_chained_public_key_alg_info(chained_public_key));

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, error);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, error);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(l1_cipher_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_public_key(vscf_key_alg_api(l2_cipher_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Export.
    //
    raw_l1_cipher_key = vscf_key_alg_export_public_key(l1_cipher_key_alg, l1_cipher_key, error);
    if (NULL == raw_l1_cipher_key) {
        goto cleanup;
    }
    raw_l1_cipher_key_len = vscf_raw_public_key_data(raw_l1_cipher_key).len;

    raw_l2_cipher_key = vscf_key_alg_export_public_key(l2_cipher_key_alg, l2_cipher_key, error);
    if (NULL == raw_l2_cipher_key) {
        goto cleanup;
    }
    raw_l2_cipher_key_len = vscf_raw_public_key_data(raw_l2_cipher_key).len;

    //
    // Write to the ASN.1 structure.
    //
    // ChainedPrivateKey ::= SEQUENCE {
    //     l1CipherKey OCTET STRING,
    //     l2CipherKey OCTET STRING
    // }
    //
    raw_key_buf_len = 1 + 4 +                         // ChainedPublicKey ::= SEQUENCE {
                      1 + 4 + raw_l1_cipher_key_len + //     l1CipherKey OCTET STRING,
                      1 + 4 + raw_l2_cipher_key_len;  //     l2CipherKey OCTET STRING }

    vsc_buffer_alloc(raw_key_buf, raw_key_buf_len);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(raw_key_buf), vsc_buffer_unused_len(raw_key_buf));

    //
    //  Write.
    //
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_l2_cipher_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_public_key_data(raw_l1_cipher_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, false);
    vsc_buffer_inc_used(raw_key_buf, raw_key_len);

    raw_key = vscf_raw_public_key_new_with_buffer(&raw_key_buf, &alg_info);

cleanup:
    vscf_asn1wr_cleanup(&asn1wr);
    vscf_raw_public_key_destroy(&raw_l1_cipher_key);
    vscf_raw_public_key_destroy(&raw_l2_cipher_key);
    vsc_buffer_destroy(&raw_key_buf);
    vscf_impl_destroy(&alg_info);
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    return raw_key;
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
vscf_chained_key_alg_import_private_key(
        const vscf_chained_key_alg_t *self, const vscf_raw_private_key_t *raw_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(raw_key);
    VSCF_ASSERT_SAFE(vscf_raw_private_key_is_valid(raw_key));

    //
    //  Check if raw key is appropriate.
    //
    const vscf_impl_t *alg_info = vscf_raw_private_key_alg_info(raw_key);
    if (vscf_impl_tag(alg_info) != vscf_impl_tag_CHAINED_KEY_ALG_INFO) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM);
        return NULL;
    }
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_CHAINED_KEY);

    //
    // Write to the ASN.1 structure.
    //
    // ChainedPrivateKey ::= SEQUENCE {
    //     l1CipherKey OCTET STRING,
    //     l2CipherKey OCTET STRING
    // }
    //
    vscf_asn1rd_t asn1rd;
    vscf_asn1rd_init(&asn1rd);
    vscf_asn1rd_reset(&asn1rd, vscf_raw_private_key_data(raw_key));
    vscf_asn1rd_read_sequence(&asn1rd);

    vsc_data_t l1_cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);
    vsc_data_t l2_cipher_key_data = vscf_asn1rd_read_octet_str(&asn1rd);

    const vscf_status_t asn1_status = vscf_asn1rd_status(&asn1rd);
    vscf_asn1rd_cleanup(&asn1rd);

    if (asn1_status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_BAD_CHAINED_PRIVATE_KEY);
        return NULL;
    }

    //
    //  Prepare keys to be imported.
    //
    const vscf_chained_key_alg_info_t *chained_key_alg_info = (const vscf_chained_key_alg_info_t *)alg_info;
    const vscf_impl_t *l1_cipher_alg_info = vscf_chained_key_alg_info_l1_cipher_alg_info(chained_key_alg_info);
    const vscf_impl_t *l2_cipher_alg_info = vscf_chained_key_alg_info_l2_cipher_alg_info(chained_key_alg_info);

    vscf_impl_t *l1_cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(l1_cipher_alg_info);
    vscf_raw_private_key_t *raw_l1_cipher_key =
            vscf_raw_private_key_new_with_data(l1_cipher_key_data, &l1_cipher_alg_info_copy);

    vscf_impl_t *l2_cipher_alg_info_copy = (vscf_impl_t *)vscf_impl_shallow_copy_const(l2_cipher_alg_info);
    vscf_raw_private_key_t *raw_l2_cipher_key =
            vscf_raw_private_key_new_with_data(l2_cipher_key_data, &l2_cipher_alg_info_copy);

    //
    //  Prepare result variables.
    //
    vscf_impl_t *l1_cipher_key_alg = NULL;
    vscf_impl_t *l1_cipher_key = NULL;
    vscf_impl_t *l2_cipher_key_alg = NULL;
    vscf_impl_t *l2_cipher_key = NULL;
    vscf_impl_t *private_key = NULL;

    //
    //  Get correspond algs.
    //
    l1_cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(l1_cipher_alg_info), self->random, error);

    if (NULL == l1_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l1_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    l2_cipher_key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_info_alg_id(l2_cipher_alg_info), self->random, error);

    if (NULL == l2_cipher_key_alg) {
        goto cleanup;
    }

    if (!vscf_key_cipher_is_implemented(l2_cipher_key_alg)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Import keys.
    //
    l1_cipher_key = vscf_key_alg_import_private_key(l1_cipher_key_alg, raw_l1_cipher_key, error);
    if (NULL == l1_cipher_key) {
        goto cleanup;
    }

    l2_cipher_key = vscf_key_alg_import_private_key(l2_cipher_key_alg, raw_l2_cipher_key, error);
    if (NULL == l2_cipher_key) {
        goto cleanup;
    }

    //
    //  Make chained key.
    //
    private_key = vscf_chained_private_key_impl(
            vscf_chained_private_key_new_with_imported_keys(alg_info, &l1_cipher_key, &l2_cipher_key));

cleanup:
    vscf_raw_private_key_destroy(&raw_l1_cipher_key);
    vscf_raw_private_key_destroy(&raw_l2_cipher_key);
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l1_cipher_key);
    vscf_impl_destroy(&l2_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key);

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
vscf_chained_key_alg_export_private_key(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    //
    //  Prepare keys.
    //
    if (vscf_key_impl_tag(private_key) != self->info->impl_tag) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM);
        return NULL;
    }

    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_CHAINED_PRIVATE_KEY);
    const vscf_chained_private_key_t *chained_private_key = (const vscf_chained_private_key_t *)private_key;

    const vscf_impl_t *l1_cipher_key = vscf_chained_private_key_l1_cipher_key(chained_private_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_private_key_l2_cipher_key(chained_private_key);

    //
    //  Prepare result variables.
    //
    vscf_asn1wr_t asn1wr;
    vscf_asn1wr_init(&asn1wr);

    vsc_buffer_t *raw_key_buf = vsc_buffer_new();
    size_t raw_key_buf_len = 0;

    vscf_raw_private_key_t *raw_key = NULL;
    size_t raw_key_len = 0;

    vscf_raw_private_key_t *raw_l1_cipher_key = NULL;
    size_t raw_l1_cipher_key_len = 0;

    vscf_raw_private_key_t *raw_l2_cipher_key = NULL;
    size_t raw_l2_cipher_key_len = 0;

    //
    //  Create correspond algs.
    //
    vscf_impl_t *alg_info =
            (vscf_impl_t *)vscf_impl_shallow_copy_const(vscf_chained_private_key_alg_info(chained_private_key));

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, error);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, error);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    //
    //  Check if keys are exportable.
    //
    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(l1_cipher_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    if (!vscf_key_alg_can_export_private_key(vscf_key_alg_api(l2_cipher_key_alg))) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
        goto cleanup;
    }

    //
    //  Export.
    //
    raw_l1_cipher_key = vscf_key_alg_export_private_key(l1_cipher_key_alg, l1_cipher_key, error);
    if (NULL == raw_l1_cipher_key) {
        goto cleanup;
    }
    raw_l1_cipher_key_len = vscf_raw_private_key_data(raw_l1_cipher_key).len;

    raw_l2_cipher_key = vscf_key_alg_export_private_key(l2_cipher_key_alg, l2_cipher_key, error);
    if (NULL == raw_l2_cipher_key) {
        goto cleanup;
    }
    raw_l2_cipher_key_len = vscf_raw_private_key_data(raw_l2_cipher_key).len;

    //
    // Write to the ASN.1 structure.
    //
    // ChainedPrivateKey ::= SEQUENCE {
    //     l1CipherKey OCTET STRING,
    //     l2CipherKey OCTET STRING
    // }
    //
    raw_key_buf_len = 1 + 4 +                         // ChainedPrivateKey ::= SEQUENCE {
                      1 + 4 + raw_l1_cipher_key_len + //     l1CipherKey OCTET STRING,
                      1 + 4 + raw_l2_cipher_key_len;  //     l2CipherKey OCTET STRING }

    vsc_buffer_alloc(raw_key_buf, raw_key_buf_len);
    vscf_asn1wr_reset(&asn1wr, vsc_buffer_unused_bytes(raw_key_buf), vsc_buffer_unused_len(raw_key_buf));

    //
    //  Write.
    //
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_l2_cipher_key));
    raw_key_len += vscf_asn1wr_write_octet_str(&asn1wr, vscf_raw_private_key_data(raw_l1_cipher_key));
    raw_key_len += vscf_asn1wr_write_sequence(&asn1wr, raw_key_len);
    VSCF_ASSERT(!vscf_asn1wr_has_error(&asn1wr));

    vscf_asn1wr_finish(&asn1wr, false);
    vsc_buffer_inc_used(raw_key_buf, raw_key_len);

    raw_key = vscf_raw_private_key_new_with_buffer(&raw_key_buf, &alg_info);

cleanup:
    vscf_asn1wr_cleanup(&asn1wr);
    vscf_raw_private_key_destroy(&raw_l1_cipher_key);
    vscf_raw_private_key_destroy(&raw_l2_cipher_key);
    vsc_buffer_destroy(&raw_key_buf);
    vscf_impl_destroy(&alg_info);
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    return raw_key;
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_chained_key_alg_can_encrypt(const vscf_chained_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_CHAINED_PUBLIC_KEY);

    const vscf_chained_public_key_t *chained_public_key = (const vscf_chained_public_key_t *)public_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_public_key_l1_cipher_key(chained_public_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_public_key_l2_cipher_key(chained_public_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const bool l1_cipher_can_encrypt = vscf_key_cipher_can_encrypt(l1_cipher_key_alg, l1_cipher_key, data_len);
    const size_t l1_encrypted_len = vscf_key_cipher_encrypted_len(l1_cipher_key_alg, l1_cipher_key, data_len);
    const bool l2_cipher_can_encrypt = vscf_key_cipher_can_encrypt(l2_cipher_key_alg, l2_cipher_key, l1_encrypted_len);

    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    return l1_cipher_can_encrypt && l2_cipher_can_encrypt;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_chained_key_alg_encrypted_len(const vscf_chained_key_alg_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_CHAINED_PUBLIC_KEY);

    const vscf_chained_public_key_t *chained_public_key = (const vscf_chained_public_key_t *)public_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_public_key_l1_cipher_key(chained_public_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_public_key_l2_cipher_key(chained_public_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const size_t l1_encrypted_len = vscf_key_cipher_encrypted_len(l1_cipher_key_alg, l1_cipher_key, data_len);
    const size_t l2_encrypted_len = vscf_key_cipher_encrypted_len(l2_cipher_key_alg, l2_cipher_key, l1_encrypted_len);

    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    if (l1_encrypted_len == 0 || l2_encrypted_len == 0) {
        return 0;
    }

    return l2_encrypted_len;
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_chained_key_alg_encrypt(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_impl_tag(public_key) == vscf_impl_tag_CHAINED_PUBLIC_KEY);
    VSCF_ASSERT(vscf_chained_key_alg_can_encrypt(self, public_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chained_key_alg_encrypted_len(self, public_key, data.len));

    const vscf_chained_public_key_t *chained_public_key = (const vscf_chained_public_key_t *)public_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_public_key_l1_cipher_key(chained_public_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_public_key_l2_cipher_key(chained_public_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const size_t l1_out_capacity = vscf_key_cipher_encrypted_len(l1_cipher_key_alg, l1_cipher_key, data.len);
    vsc_buffer_t *l1_out = vsc_buffer_new_with_capacity(l1_out_capacity);

    vscf_status_t status = vscf_key_cipher_encrypt(l1_cipher_key_alg, l1_cipher_key, data, l1_out);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    status = vscf_key_cipher_encrypt(l2_cipher_key_alg, l2_cipher_key, vsc_buffer_data(l1_out), out);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

cleanup:
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);
    vsc_buffer_destroy(&l1_out);
    return status;
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_chained_key_alg_can_decrypt(const vscf_chained_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_CHAINED_PRIVATE_KEY);

    const vscf_chained_private_key_t *chained_private_key = (const vscf_chained_private_key_t *)private_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_private_key_l1_cipher_key(chained_private_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_private_key_l2_cipher_key(chained_private_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const bool l2_cipher_can_decrypt = vscf_key_cipher_can_decrypt(l2_cipher_key_alg, l2_cipher_key, data_len);
    const size_t l2_decrypted_len = vscf_key_cipher_decrypted_len(l2_cipher_key_alg, l2_cipher_key, data_len);
    const bool l1_cipher_can_decrypt = vscf_key_cipher_can_decrypt(l1_cipher_key_alg, l1_cipher_key, l2_decrypted_len);

    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    return l1_cipher_can_decrypt && l2_cipher_can_decrypt;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_chained_key_alg_decrypted_len(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_CHAINED_PRIVATE_KEY);

    const vscf_chained_private_key_t *chained_private_key = (const vscf_chained_private_key_t *)private_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_private_key_l1_cipher_key(chained_private_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_private_key_l2_cipher_key(chained_private_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const size_t l2_decrypted_len = vscf_key_cipher_decrypted_len(l2_cipher_key_alg, l2_cipher_key, data_len);
    const size_t l1_decrypted_len = vscf_key_cipher_decrypted_len(l1_cipher_key_alg, l1_cipher_key, l2_decrypted_len);

    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);

    if (l1_decrypted_len == 0 || l2_decrypted_len == 0) {
        return 0;
    }

    return l1_decrypted_len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_chained_key_alg_decrypt(
        const vscf_chained_key_alg_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_impl_tag(private_key) == vscf_impl_tag_CHAINED_PRIVATE_KEY);
    VSCF_ASSERT(vscf_chained_key_alg_can_decrypt(self, private_key, data.len));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_chained_key_alg_decrypted_len(self, private_key, data.len));

    const vscf_chained_private_key_t *chained_private_key = (const vscf_chained_private_key_t *)private_key;
    const vscf_impl_t *l1_cipher_key = vscf_chained_private_key_l1_cipher_key(chained_private_key);
    const vscf_impl_t *l2_cipher_key = vscf_chained_private_key_l2_cipher_key(chained_private_key);

    vscf_impl_t *l1_cipher_key_alg = vscf_key_alg_factory_create_from_key(l1_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l1_cipher_key_alg);

    vscf_impl_t *l2_cipher_key_alg = vscf_key_alg_factory_create_from_key(l2_cipher_key, self->random, NULL);
    VSCF_ASSERT_PTR(l2_cipher_key_alg);

    const size_t l2_out_capacity = vscf_key_cipher_decrypted_len(l2_cipher_key_alg, l2_cipher_key, data.len);
    vsc_buffer_t *l2_out = vsc_buffer_new_with_capacity(l2_out_capacity);

    vscf_status_t status = vscf_key_cipher_decrypt(l2_cipher_key_alg, l2_cipher_key, data, l2_out);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

    status = vscf_key_cipher_decrypt(l1_cipher_key_alg, l1_cipher_key, vsc_buffer_data(l2_out), out);
    if (status != vscf_status_SUCCESS) {
        goto cleanup;
    }

cleanup:
    vscf_impl_destroy(&l1_cipher_key_alg);
    vscf_impl_destroy(&l2_cipher_key_alg);
    vsc_buffer_destroy(&l2_out);
    return status;
}
