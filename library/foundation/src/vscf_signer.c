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
//  Sign data of any size.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_signer.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_hash.h"
#include "vscf_signer_defs.h"
#include "vscf_sha384.h"
#include "vscf_alg.h"
#include "vscf_sign_hash.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_signer_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_signer_init_ctx(vscf_signer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_signer_cleanup_ctx(vscf_signer_t *self);

//
//  Return size of 'vscf_signer_t'.
//
VSCF_PUBLIC size_t
vscf_signer_ctx_size(void) {

    return sizeof(vscf_signer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_signer_init(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_signer_t));

    self->refcnt = 1;

    vscf_signer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_signer_cleanup(vscf_signer_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_signer_cleanup_ctx(self);

        vscf_signer_release_hash(self);

        vscf_zeroize(self, sizeof(vscf_signer_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_signer_t *
vscf_signer_new(void) {

    vscf_signer_t *self = (vscf_signer_t *) vscf_alloc(sizeof (vscf_signer_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_signer_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_signer_delete(vscf_signer_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_signer_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_signer_new ()'.
//
VSCF_PUBLIC void
vscf_signer_destroy(vscf_signer_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_signer_t *self = *self_ref;
    *self_ref = NULL;

    vscf_signer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_signer_t *
vscf_signer_shallow_copy(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Setup dependency to the interface 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_signer_use_hash(vscf_signer_t *self, vscf_impl_t *hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT(self->hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(hash));

    self->hash = vscf_impl_shallow_copy(hash);
}

//
//  Setup dependency to the interface 'hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_signer_take_hash(vscf_signer_t *self, vscf_impl_t *hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT_PTR(self->hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(hash));

    self->hash = hash;
}

//
//  Release dependency to the interface 'hash'.
//
VSCF_PUBLIC void
vscf_signer_release_hash(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->hash);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_signer_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_signer_init_ctx(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    self->asn1wr = vscf_asn1wr_new();
    self->alg_info_der_serializer = vscf_alg_info_der_serializer_new();
    vscf_alg_info_der_serializer_use_asn1_writer(self->alg_info_der_serializer, vscf_asn1wr_impl(self->asn1wr));
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_signer_cleanup_ctx(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_asn1wr_destroy(&self->asn1wr);
    vscf_alg_info_der_serializer_destroy(&self->alg_info_der_serializer);
}

//
//  Start a processing a new signature.
//
VSCF_PUBLIC void
vscf_signer_reset(vscf_signer_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->hash) {
        self->hash = vscf_sha384_impl(vscf_sha384_new());
    }

    vscf_hash_start(self->hash);
}

//
//  Add given data to the signed data.
//
VSCF_PUBLIC void
vscf_signer_update(vscf_signer_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT(vsc_data_is_valid(data));

    vscf_hash_update(self->hash, data);
}

//
//  Return length of the signature.
//
VSCF_PUBLIC size_t
vscf_signer_signature_len(vscf_signer_t *self, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_sign_hash_is_implemented(private_key));

    size_t signature_len = vscf_sign_hash_signature_len(private_key);
    size_t len = 1 + 1 +                //  VirgilSignature ::= SEQUENCE {
                 1 + 1 + 32 +           //      digestAlgorithm ::= AlgorithmIdentifier,
                 1 + 4 + signature_len; //      signature ::= OCTET STRING }

    return len;
}

//
//  Accomplish signing and return signature.
//
VSCF_PUBLIC vscf_status_t
vscf_signer_sign(vscf_signer_t *self, vscf_impl_t *private_key, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT_PTR(self->asn1wr);
    VSCF_ASSERT_PTR(self->alg_info_der_serializer);
    VSCF_ASSERT(vscf_sign_hash_is_implemented(private_key));
    VSCF_ASSERT_PTR(signature);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(vsc_buffer_unused_len(signature) >= vscf_signer_signature_len(self, private_key));

    //
    //  Get digest.
    //
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_hash_digest_len(vscf_hash_api(self->hash)));
    vscf_hash_finish(self->hash, digest);

    //
    // Get raw signature.
    //
    vsc_buffer_t *raw_signature = vsc_buffer_new_with_capacity(vscf_sign_hash_signature_len(private_key));
    vscf_status_t status =
            vscf_sign_hash(private_key, vsc_buffer_data(digest), vscf_alg_alg_id(self->hash), raw_signature);

    vsc_buffer_destroy(&digest);
    if (status != vscf_status_SUCCESS) {
        vsc_buffer_destroy(&raw_signature);
        return status;
    }

    //
    // Wrap raw signature to the ASN.1 structure.
    //
    vscf_asn1wr_reset(self->asn1wr, vsc_buffer_unused_bytes(signature), vsc_buffer_unused_len(signature));

    size_t len = 0;

    vscf_impl_t *hash_alg_info = vscf_alg_produce_alg_info(self->hash);
    len += vscf_asn1wr_write_octet_str(self->asn1wr, vsc_buffer_data(raw_signature));
    len += vscf_alg_info_der_serializer_serialize_inplace(self->alg_info_der_serializer, hash_alg_info);
    len += vscf_asn1wr_write_sequence(self->asn1wr, len);
    vscf_impl_destroy(&hash_alg_info);
    vsc_buffer_destroy(&raw_signature);

    if (vscf_asn1wr_has_error(self->asn1wr)) {
        return vscf_asn1wr_status(self->asn1wr);
    }

    vscf_asn1wr_finish(self->asn1wr, vsc_buffer_is_reverse(signature));
    vsc_buffer_inc_used(signature, len);

    return vscf_status_SUCCESS;
}
