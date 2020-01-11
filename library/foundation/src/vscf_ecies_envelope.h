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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


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

#ifndef VSCF_ECIES_ENVELOPE_H_INCLUDED
#define VSCF_ECIES_ENVELOPE_H_INCLUDED

#include "vscf_library.h"
#include "vscf_raw_public_key.h"
#include "vscf_impl.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ecies envelope' context.
//
typedef struct vscf_ecies_envelope_t vscf_ecies_envelope_t;
struct vscf_ecies_envelope_t {
    vscf_raw_public_key_t *ephemeral_public_key;

    vscf_impl_t *cipher;

    vscf_impl_t *kdf;

    vscf_impl_t *mac;

    vsc_buffer_t *mac_digest;

    vsc_buffer_t *encrypted_content;
};

//
//  Return size of 'vscf_ecies_envelope_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_ctx_size(void);

//
//  Return buffer length required to hold packed ECIES-Envelope.
//
VSCF_PUBLIC size_t
vscf_ecies_envelope_packed_len(vscf_ecies_envelope_t *self);

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
VSCF_PUBLIC vscf_status_t
vscf_ecies_envelope_pack(vscf_ecies_envelope_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

//
//  Unpack ECIES-Envelope ASN.1 structure.
//  Unpacked data can be accessed thru getters.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_envelope_unpack(vscf_ecies_envelope_t *self, vsc_data_t data) VSCF_NODISCARD;

//
//  Destroy internal objects.
//
VSCF_PUBLIC void
vscf_ecies_envelope_cleanup_properties(vscf_ecies_envelope_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ECIES_ENVELOPE_H_INCLUDED
//  @end
