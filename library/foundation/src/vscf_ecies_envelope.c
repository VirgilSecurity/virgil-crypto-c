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
//  Provides function to process ECIES envelope ASN.1 structure:
//
//      ECIES-Envelope-Schema DEFINITIONS EXPLICIT TAGS ::=
//      BEGIN
//
//         IMPORTS
//
//           -- Imports from RFC 5280, Appendix A.1
//              AlgorithmIdentifier
//                  FROM PKIX1Explicit88
//                      { iso(1) identified-organization(3) dod(6)
//                        internet(1) security(5) mechanisms(5) pkix(7)
//                        mod(0) pkix1-explicit(18) }
//
//           -- Imports from ISO/IEC 18033-2, Appendix B
//              KeyDerivationFunction
//                  FROM AlgorithmObjectIdentifiers
//                      { iso(1) standard(0) encryption-algorithms(18033) part(2)
//                        asn1-module(0) algorithm-object-identifiers(0) };
//
//
//          ECIES-Envelope ::= SEQUENCE {
//              version          INTEGER { v0(0) },
//              originator       OriginatorPublicKey,
//              kdf              KeyDerivationFunction,
//              hmac             DigestInfo,
//              encryptedContent EncryptedContentInfo
//          }
//
//          OriginatorPublicKey ::= SEQUENCE {
//              algorithm AlgorithmIdentifier,
//              publicKey BIT STRING
//          }
//
//          DigestInfo ::= SEQUENCE {
//              digestAlgorithm    DigestAlgorithmIdentifier,
//              digest             Digest
//          }
//
//          DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//
//          Digest ::= OCTET STRING
//
//          EncryptedContentInfo ::= SEQUENCE {
//              contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//              encryptedContent EncryptedContent
//          }
//
//          ContentEncryptionAlgorithmIdentifier :: = AlgorithmIdentifier
//
//          EncryptedContent ::= OCTET STRING
//      END
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecies_envelope.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ecies_envelope_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_envelope_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_envelope_init_ctx(vscf_ecies_envelope_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_envelope_cleanup_ctx(vscf_ecies_envelope_t *self);

//
//  Return size of 'vscf_ecies_envelope_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_ctx_size(void) {

    return sizeof(vscf_ecies_envelope_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_ecies_envelope_init(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ecies_envelope_t));

    self->refcnt = 1;

    vscf_ecies_envelope_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_ecies_envelope_cleanup(vscf_ecies_envelope_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_ecies_envelope_cleanup_ctx(self);

        vscf_zeroize(self, sizeof(vscf_ecies_envelope_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_ecies_envelope_t *
vscf_ecies_envelope_new(void) {

    vscf_ecies_envelope_t *self = (vscf_ecies_envelope_t *) vscf_alloc(sizeof (vscf_ecies_envelope_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ecies_envelope_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_ecies_envelope_delete(vscf_ecies_envelope_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_ecies_envelope_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_ecies_envelope_new ()'.
//
VSCF_PUBLIC void
vscf_ecies_envelope_destroy(vscf_ecies_envelope_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ecies_envelope_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ecies_envelope_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_ecies_envelope_t *
vscf_ecies_envelope_shallow_copy(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_envelope_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_envelope_init_ctx(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    //  Nothing to be done.
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_envelope_cleanup_ctx(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    //  Nothing to be done.
}

//
//  Set "originator".
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_originator(vscf_ecies_envelope_t *self, vscf_impl_t *originator) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(originator);

    self->originator = originator;
}

//
//  Set "kdf" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_kdf(vscf_ecies_envelope_t *self, vscf_impl_t *kdf) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(kdf);

    self->kdf = kdf;
}

//
//  Set "mac" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_mac(vscf_ecies_envelope_t *self, vscf_impl_t *mac) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac);

    self->mac = mac;
}

//
//  Set "mac" digest.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_mac_digest(vscf_ecies_envelope_t *self, vsc_buffer_t *mac_digest) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac_digest);

    self->mac_digest = mac_digest;
}

//
//  Set "cipher" algorithm information.
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_cipher(vscf_ecies_envelope_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);

    self->cipher = cipher;
}

//
//  Set "encrypted content".
//
VSCF_PUBLIC void
vscf_ecies_envelope_set_encrypted_content(vscf_ecies_envelope_t *self, vsc_buffer_t *encrypted_content) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encrypted_content);

    self->encrypted_content = encrypted_content;
}

//
//  Return "originator".
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ecies_envelope_get_originator(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->originator);

    return self->originator;
}

//
//  Return "kdf".
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ecies_envelope_get_kdf(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->kdf);

    return self->kdf;
}

//
//  Return "mac".
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ecies_envelope_get_mac(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->mac);

    return self->mac;
}

//
//  Return "mac digest".
//
VSCF_PUBLIC vsc_buffer_t *
vscf_ecies_envelope_get_mac_digest(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->mac_digest);

    return self->mac_digest;
}

//
//  Return "cipher".
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ecies_envelope_get_cipher(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return self->cipher;
}

//
//  Return "encrypted content".
//
VSCF_PUBLIC vsc_buffer_t *
vscf_ecies_envelope_get_encrypted_content(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->encrypted_content);

    return self->encrypted_content;
}

//
//  Return buffer length required to hold packed ECIES-Envelope.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_packed_len(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->originator);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->mac);
    VSCF_ASSERT_PTR(self->mac_digest);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->encrypted_content);

    //  TODO: Implement me.
    return 256;
}

//
//  Pack properties to the ASN.1 structure.
//
//  ECIES-Envelope ::= SEQUENCE {
//      version INTEGER { v0(0) },
//      originator OriginatorPublicKey,
//      kdf KeyDerivationFunction,
//      hmac DigestInfo,
//      encryptedContent EncryptedContentInfo }
//
//  OriginatorPublicKey ::= SEQUENCE {
//      algorithm AlgorithmIdentifier,
//      publicKey BIT STRING }
//
//  DigestInfo ::= SEQUENCE {
//      digestAlgorithm DigestAlgorithmIdentifier,
//      digest Digest }
//
//  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//  Digest ::= OCTET STRING
//
//  EncryptedContentInfo ::= SEQUENCE {
//      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//      encryptedContent EncryptedContent }
//
//  ContentEncryptionAlgorithmIdentifier :: = AlgorithmIdentifier
//  EncryptedContent ::= OCTET STRING
//
VSCF_PUBLIC void
vscf_ecies_envelope_pack(vscf_ecies_envelope_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->originator);
    VSCF_ASSERT_PTR(self->kdf);
    VSCF_ASSERT_PTR(self->mac);
    VSCF_ASSERT_PTR(self->mac_digest);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->encrypted_content);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_envelope_packed_len(self));
}

//
//  Unpack ECIES-Envelope ASN.1 structure.
//  Unpacked data can be accessed thru getters.
//
VSCF_PUBLIC vscf_error_t
vscf_ecies_envelope_unpack(vscf_ecies_envelope_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_SUCCESS;
}
