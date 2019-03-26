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
//  This module contains 'iotelic private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_iotelic_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_iotelic_public_key.h"
#include "vscf_iotelic_private_key_defs.h"
#include "vscf_iotelic_private_key_internal.h"

#include <iotelic_sp_interface.h>

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
//  Note, this method is called automatically when method vscf_iotelic_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_iotelic_private_key_init_ctx(vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_iotelic_private_key_cleanup_ctx(vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.
}

//
//  Create private key with specific slot id.
//
VSCF_PUBLIC vscf_iotelic_private_key_t *
vscf_iotelic_private_key_new_with_slot_id(size_t slot_id) {

    VSCF_UNUSED(slot_id);

    vscf_iotelic_private_key_t *self = vscf_iotelic_private_key_new();

    //   TODO: Perform initialization.

    return self;
}

//
//  Generate new private with a given slot id.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_generate_key(vscf_iotelic_private_key_t *self, size_t slot_id, vscf_alg_id_t alg_id) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(slot_id);
    VSCF_UNUSED(alg_id);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_iotelic_private_key_alg_id(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return vscf_alg_id_NONE;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_private_key_produce_alg_info(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_restore_alg_info(vscf_iotelic_private_key_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_key_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_key_bitlen(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_signature_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_sign_hash(
        vscf_iotelic_private_key_t *self, vsc_data_t hash_digest, vscf_alg_id_t hash_id, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(hash_digest);
    VSCF_UNUSED(hash_id);
    VSCF_UNUSED(signature);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_iotelic_private_key_extract_public_key(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return NULL;
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_export_private_key(const vscf_iotelic_private_key_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_iotelic_private_key_exported_private_key_len(const vscf_iotelic_private_key_t *self) {

    VSCF_ASSERT_PTR(self);

    //  TODO: This is STUB. Implement me.

    return 0;
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_status_t
vscf_iotelic_private_key_import_private_key(vscf_iotelic_private_key_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_UNUSED(data);

    //  TODO: This is STUB. Implement me.

    return vscf_status_ERROR_BAD_ARGUMENTS;
}
