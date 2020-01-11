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
//  ASN.1 constants.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1_TAG_H_INCLUDED
#define VSCF_ASN1_TAG_H_INCLUDED

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
//  ASN.1 constants.
//
enum vscf_asn1_tag_t {
    vscf_asn1_tag_BOOLEAN = 0x01,
    vscf_asn1_tag_INTEGER = 0x02,
    vscf_asn1_tag_BIT_STRING = 0x03,
    vscf_asn1_tag_OCTET_STRING = 0x04,
    vscf_asn1_tag_NULL = 0x05,
    vscf_asn1_tag_OID = 0x06,
    vscf_asn1_tag_UTF8_STRING = 0x0C,
    vscf_asn1_tag_SEQUENCE = 0x10,
    vscf_asn1_tag_SET = 0x11,
    vscf_asn1_tag_PRINTABLE_STRING = 0x13,
    vscf_asn1_tag_T61_STRING = 0x14,
    vscf_asn1_tag_IA5_STRING = 0x16,
    vscf_asn1_tag_UTC_TIME = 0x17,
    vscf_asn1_tag_GENERALIZED_TIME = 0x18,
    vscf_asn1_tag_UNIVERSAL_STRING = 0x1C,
    vscf_asn1_tag_BMP_STRING = 0x1E,
    vscf_asn1_tag_PRIMITIVE = 0x00,
    vscf_asn1_tag_CONSTRUCTED = 0x20,
    vscf_asn1_tag_CONTEXT_SPECIFIC = 0x80
};
typedef enum vscf_asn1_tag_t vscf_asn1_tag_t;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ASN1_TAG_H_INCLUDED
//  @end
