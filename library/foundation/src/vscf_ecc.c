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
//  This module contains 'ecc' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecc.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_asn1rd.h"
#include "vscf_asn1wr.h"
#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_mbedtls_md.h"
#include "vscf_ec_alg_info.h"
#include "vscf_asn1_tag.h"
#include "vscf_ctr_drbg.h"
#include "vscf_alg_info.h"
#include "vscf_alg.h"
#include "vscf_mbedtls_bridge_random.h"
#include "vscf_ecc_public_key_defs.h"
#include "vscf_ecc_private_key_defs.h"
#include "vscf_random.h"
#include "vscf_ecc_defs.h"
#include "vscf_ecc_internal.h"

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
vscf_ecc_setup_defaults(vscf_ecc_t *self) {

    //  TODO: This is STUB. Implement me.
}

//
//  Generate new private key.
//  Supported algorithm ids:
//      - secp256r1.
//
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_generate_key(const vscf_ecc_t *self, vscf_alg_id_t alg_id, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_ecc_alg_id(const vscf_ecc_t *self) {

    //  TODO: This is STUB. Implement me.
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_produce_alg_info(const vscf_ecc_t *self) {

    //  TODO: This is STUB. Implement me.
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_restore_alg_info(vscf_ecc_t *self, const vscf_impl_t *alg_info) {

    //  TODO: This is STUB. Implement me.
}

//
//  Extract public key from the private key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_extract_public_key(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
}

//
//  Generate ephemeral private key of the same type.
//  Note, this operation might be slow.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecc_generate_ephemeral_key(const vscf_ecc_t *self, const vscf_impl_t *key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
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
vscf_ecc_import_public_key(vscf_ecc_t *self, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
}

//
//  Export public key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA public key must be exported in format defined in
//  RFC 3447 Appendix A.1.1.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_ecc_export_public_key(const vscf_ecc_t *self, const vscf_impl_t *public_key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
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
vscf_ecc_import_private_key(vscf_ecc_t *self, const vscf_raw_key_t *raw_key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
}

//
//  Export private key in the raw binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_raw_key_t *
vscf_ecc_export_private_key(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_error_t *error) {

    //  TODO: This is STUB. Implement me.
}

//
//  Check if algorithm can encrypt data with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_encrypt(const vscf_ecc_t *self, const vscf_impl_t *public_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_encrypt(const vscf_ecc_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    //  TODO: This is STUB. Implement me.
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ecc_encrypted_len(const vscf_ecc_t *self, const vscf_impl_t *public_key, size_t data_len) {

    //  TODO: This is STUB. Implement me.
}

//
//  Check if algorithm can decrypt data with a given key.
//  However, success result of decryption is not guaranteed.
//
VSCF_PUBLIC bool
vscf_ecc_can_decrypt(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_decrypt(const vscf_ecc_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    //  TODO: This is STUB. Implement me.
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ecc_decrypted_len(const vscf_ecc_t *self, const vscf_impl_t *private_key, size_t data_len) {

    //  TODO: This is STUB. Implement me.
}

//
//  Check if algorithm can sign data digest with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_sign(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Return length in bytes required to hold signature.
//  Return zero if a given private key can not produce signatures.
//
VSCF_PUBLIC size_t
vscf_ecc_signature_len(const vscf_ecc_t *self, const vscf_impl_t *private_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Sign data digest with a given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_sign(const vscf_ecc_t *self, const vscf_impl_t *private_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_buffer_t *signature) {

    //  TODO: This is STUB. Implement me.
}

//
//  Check if algorithm can verify data digest with a given key.
//
VSCF_PUBLIC bool
vscf_ecc_can_verify(const vscf_ecc_t *self, const vscf_impl_t *public_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Verify data digest with a given public key and signature.
//
VSCF_PUBLIC bool
vscf_ecc_verify(const vscf_ecc_t *self, const vscf_impl_t *public_key, vscf_alg_id_t hash_id, vsc_data_t digest,
        vsc_data_t signature) {

    //  TODO: This is STUB. Implement me.
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, computed shared key can be used only within symmetric cryptography.
//
VSCF_PUBLIC vscf_status_t
vscf_ecc_compute_shared_key(
        const vscf_ecc_t *self, vscf_impl_t *public_key, vscf_impl_t *private_key, vsc_buffer_t *shared_key) {

    //  TODO: This is STUB. Implement me.
}

//
//  Return number of bytes required to hold shared key.
//  Expect Public Key or Private Key.
//
VSCF_PUBLIC size_t
vscf_ecc_shared_key_len(const vscf_ecc_t *self, const vscf_impl_t *key) {

    //  TODO: This is STUB. Implement me.
}
