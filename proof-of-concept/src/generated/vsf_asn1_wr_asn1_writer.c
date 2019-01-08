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


//  @description
// --------------------------------------------------------------------------
//  Implementaion of the interface 'asn1_writer'.
//
//  Provides interface to the ASN.1 writer.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

#include "vsf_asn1_wr_asn1_writer.h"
#include "vsf_asn1_wr_private.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


// ==========================================================================
//  Functions to be implemented.
// ==========================================================================

//  Reset all internal states and prepare to new ASN.1 writing operations.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_reset (vsf_asn1_wr_t *impl, size_t capacity) {
    //  TODO: This is STUB. Implement me.
}

//  Returns the result ASN.1 structure.
VSF_PUBLIC const byte *
vsf_asn1_wr_asn1_writer_finish (vsf_asn1_wr_t *impl) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: INTEGER.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_int (vsf_asn1_wr_t *impl, int val) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: BOOLEAN.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_bool (vsf_asn1_wr_t *impl, int val) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: NULL.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_null (vsf_asn1_wr_t *impl) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: OCTET STRING.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_octet_string (vsf_asn1_wr_t *impl, const byte *data) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_utf8_string (vsf_asn1_wr_t *impl, const byte *data) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: UTF8String.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_tag (vsf_asn1_wr_t *impl, size_t tag) {
    //  TODO: This is STUB. Implement me.
}

//  Write preformatted ASN.1 structure.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_data (vsf_asn1_wr_t *impl, const byte *data) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: OID.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_oid (vsf_asn1_wr_t *impl, const byte *oid) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: SEQUENCE.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_sequence (vsf_asn1_wr_t *impl, const byte *data) {
    //  TODO: This is STUB. Implement me.
}

//  Write ASN.1 type: SET OF ANY.
VSF_PUBLIC int
vsf_asn1_wr_asn1_writer_write_set (vsf_asn1_wr_t *impl, const byte *ar, size_t ar_sz) {
    //  TODO: This is STUB. Implement me.
}
