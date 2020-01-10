#   @license
#   -------------------------------------------------------------------------
#   Copyright (C) 2015-2020 Virgil Security, Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#   -------------------------------------------------------------------------
#   @end


include_guard()

if(NOT TARGET ed25519)
    message(FATAL_ERROR "Expected target 'ed25519' to be defined first.")
endif()


target_sources(ed25519
        PRIVATE
            # COMMON
            "${CMAKE_CURRENT_LIST_DIR}/include/ed25519/ed25519.h"
            "${CMAKE_CURRENT_LIST_DIR}/include/ed25519/ed25519_sha512.h"
            "${CMAKE_CURRENT_LIST_DIR}/common/ed25519_sha512.c"

            # REF10
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/base.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/base2.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/crypto_int32.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/crypto_int64.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/crypto_uint32.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/crypto_uint64.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/d.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/d2.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ed25519.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_0.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_1.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_add.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_cmov.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_copy.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_cswap.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_frombytes.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_invert.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_isnegative.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_isnonzero.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_mul.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_mul121666.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_neg.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_pow22523.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_sq.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_sq2.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_sub.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/fe_tobytes.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_add.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_add.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_double_scalarmult.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_frombytes.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_madd.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_madd.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_msub.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_msub.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p1p1_to_p2.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p1p1_to_p3.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p2_0.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p2_dbl.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p2_dbl.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p3_0.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p3_dbl.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p3_to_cached.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p3_to_p2.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_p3_tobytes.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_precomp_0.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_scalarmult_base.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_sub.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_sub.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/ge_tobytes.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/pow22523.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/pow225521.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/sc.h>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/sc_muladd.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/sc_reduce.c>"
            "$<$<BOOL:${ED25519_REF10}>:${CMAKE_CURRENT_LIST_DIR}/ref10/sqrtm1.h>"

            # ED25519_AMD64_RADIX_64_24K
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/choose_t.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/consts.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ed25519.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_add.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_freeze.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_getparity.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_invert.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_iseq.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_iszero.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_mul.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_neg.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_pack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_pow2523.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_setint.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_square.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_sub.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/fe25519_unpack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_add.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_add_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_base.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_base_niels.data>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_base_niels_smalltables.data>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_base_slide_multiples.data>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_dbl_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_double.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_double_scalarmult.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_isneutral.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_multi_scalarmult.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_nielsadd2.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_nielsadd_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_p1p1_to_p2.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_p1p1_to_p3.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_pack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_pnielsadd_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_scalarmult_base.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ge25519_unpackneg.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/heap_rootreplaced.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/heap_rootreplaced_1limb.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/heap_rootreplaced_2limbs.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/heap_rootreplaced_3limbs.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/implementors>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/index_heap.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/index_heap.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_add.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_barrett.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_from32bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_from64bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_from_shortsc.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_iszero.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_lt.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_mul.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_mul_shortsc.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_slide.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_sub_nored.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_to32bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/sc25519_window4.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_64_24K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_64_24k/ull4_mul.s>"

            # AMD64_RADIX_51_30K
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/choose_t.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/consts.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ed25519.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_add.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_freeze.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_getparity.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_invert.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_iseq.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_iszero.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_mul.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_neg.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_nsquare.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_pack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_pow2523.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_setint.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_square.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_sub.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/fe25519_unpack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_add.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_add_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_base.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_base_niels_smalltables.data>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_base_slide_multiples.data>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_dbl_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_double.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_double_scalarmult.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_isneutral.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_multi_scalarmult.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_nielsadd2.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_nielsadd_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_p1p1_to_p2.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_p1p1_to_p3.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_p1p1_to_pniels.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_pack.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_pnielsadd_p1p1.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_scalarmult_base.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ge25519_unpackneg.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/heap_rootreplaced.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/heap_rootreplaced_1limb.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/heap_rootreplaced_2limbs.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/heap_rootreplaced_3limbs.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/implementors>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/index_heap.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/index_heap.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519.h>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_add.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_barrett.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_from32bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_from64bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_from_shortsc.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_iszero.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_lt.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_mul.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_mul_shortsc.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_slide.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_sub_nored.s>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_to32bytes.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/sc25519_window4.c>"
            "$<$<BOOL:${ED25519_AMD64_RADIX_51_30K}>:${CMAKE_CURRENT_LIST_DIR}/amd64_51_30k/ull4_mul.s>"
        )
