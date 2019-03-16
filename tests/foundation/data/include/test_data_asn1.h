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


#include "vsc_data.h"

//
//  Primitive types
//
extern const vsc_data_t test_asn1_encoded_INT_2;
extern const vsc_data_t test_asn1_encoded_INT_NEG_2;
extern const vsc_data_t test_asn1_encoded_BOOLEAN_TRUE;
extern const vsc_data_t test_asn1_encoded_BOOLEAN_FALSE;
extern const vsc_data_t test_asn1_encoded_NULL;

extern const vsc_data_t test_asn1_encoded_INT_0;
extern const vsc_data_t test_asn1_encoded_INT_255;
extern const vsc_data_t test_asn1_encoded_INT_32760;
extern const vsc_data_t test_asn1_encoded_INT_NEG_32760;
extern const vsc_data_t test_asn1_encoded_INT_2147483000;
extern const vsc_data_t test_asn1_encoded_INT_NEG_2147483000;
extern const vsc_data_t test_asn1_encoded_INT8_MAX;
extern const vsc_data_t test_asn1_encoded_INT8_MIN;
extern const vsc_data_t test_asn1_encoded_INT64_MAX;
extern const vsc_data_t test_asn1_encoded_INT64_MIN;
extern const vsc_data_t test_asn1_encoded_UINT16_MAX;
extern const vsc_data_t test_asn1_encoded_UINT32_MAX;
extern const vsc_data_t test_asn1_encoded_UINT64_MAX;
//
// Strings
//
extern const vsc_data_t test_asn1_encoded_OCTET_STRING;
extern const vsc_data_t test_asn1_decoded_OCTET_STRING;
extern const vsc_data_t test_asn1_encoded_UTF8_STRING;
extern const vsc_data_t test_asn1_decoded_UTF8_STRING;
extern const vsc_data_t test_asn1_encoded_OID_SHA256;
extern const vsc_data_t test_asn1_decoded_OID_SHA256;
extern const vsc_data_t test_asn1_encoded_BIT_STRING;
extern const vsc_data_t test_asn1_decoded_BIT_STRING;

//
// Containers
//
extern const vsc_data_t test_asn1_encoded_SEQUENCE_WITH_LEN_32;
extern const vsc_data_t test_asn1_encoded_SET_WITH_LEN_32;
extern const vsc_data_t test_asn1_encoded_ORDERED_SET;
extern const vsc_data_t test_asn1_SET_ELEMENT_0;
extern const vsc_data_t test_asn1_SET_ELEMENT_1;
extern const vsc_data_t test_asn1_SET_ELEMENT_2;
extern const vsc_data_t test_asn1_SET_ELEMENT_3;
