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
//  Provide method to write type 'mbedtls_mpi' ASN.1 INTEGER.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_bignum_asn1_writer.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_asn1_writer.h"
#include "vscf_asn1_tag.h"

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
//  Write given MbedTLS big number as ASN.1 INTEGER type.
//  Returns size of written data.
//
VSCF_PUBLIC size_t
vscf_mbedtls_bignum_write_asn1(vscf_impl_t *asn1wr, const mbedtls_mpi *bignum, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(bignum);
    VSCF_ASSERT_PTR(asn1wr);

    size_t bignum_len = mbedtls_mpi_size(bignum);
    byte *bignum_start = vscf_asn1_writer_reserve(asn1wr, bignum_len);

    if (NULL == bignum_start) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_writer_error(asn1wr));
        return 0;
    }

    int mpi_ret = mbedtls_mpi_write_binary(bignum, bignum_start, bignum_len);
    VSCF_ASSERT_OPT(0 == mpi_ret);

    //   if number is positive, but most left bit is one, then prepend it with zero byte
    if (1 == bignum->s && *bignum_start & 0x80) {
        bignum_start = vscf_asn1_writer_reserve(asn1wr, 1);

        if (NULL == bignum_start) {
            VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_writer_error(asn1wr));
            return 0;
        }

        *bignum_start = 0x00;
        bignum_len += 1;
    }

    size_t asn1_len = bignum_len;

    asn1_len += vscf_asn1_writer_write_len(asn1wr, bignum_len);
    asn1_len += vscf_asn1_writer_write_tag(asn1wr, vscf_asn1_tag_INTEGER);

    VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_writer_error(asn1wr));
    return asn1_len;
}
