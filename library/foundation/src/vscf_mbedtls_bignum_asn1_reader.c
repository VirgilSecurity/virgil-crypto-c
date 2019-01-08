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
//  Provide method to read type 'mbedtls_mpi' from ASN.1 INTEGER representation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_mbedtls_bignum_asn1_reader.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_asn1_reader.h"
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
//  Restore state of given MbedTLS big number from ASN.1 INTEGER representation.
//  Client side must check state of 'asn1rd' to define result of reading.
//
VSCF_PUBLIC void
vscf_mbedtls_bignum_read_asn1(vscf_impl_t *asn1rd, mbedtls_mpi *bignum, vscf_error_ctx_t *error) {

    VSCF_ASSERT_PTR(bignum);
    VSCF_ASSERT_PTR(asn1rd);

    size_t len = vscf_asn1_reader_read_tag(asn1rd, vscf_asn1_tag_INTEGER);
    vsc_data_t data = vscf_asn1_reader_read_data(asn1rd, len);

    if (NULL == data.bytes) {
        VSCF_ERROR_CTX_SAFE_UPDATE(error, vscf_asn1_reader_error(asn1rd));
        return;
    }

    int ret = mbedtls_mpi_read_binary(bignum, data.bytes, data.len);

    VSCF_ASSERT_ALLOC(ret != MBEDTLS_ERR_MPI_ALLOC_FAILED);
}
