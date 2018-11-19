//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "test_data_simple_swu.h"

const byte test_simple_swu_hash1_DEC[] = {
        "f3adca11915f1edf34a228e3aed79fbb34737f028741595410b3817e69bb6f56"
};

const byte test_simple_swu_x1_DEC[] = {
        "98961140665513202099949527671188598357073154743453831835087605751841592205265"
};

const byte test_simple_swu_y1_DEC[] = {
        "96901867652408139372430876548444592023045378705303176822621915144992255442028"
};

const byte test_simple_swu_hash2_DEC[] = {
        "0435562be4b4dc0605ef077ee015be12f3c189dcfdd830e535b076000e3d1ed3"
};

const byte test_simple_swu_x2_DEC[] = {
        "82631351409592308865866007164583686358318012812204374400003568408405894942018"
};

const byte test_simple_swu_y2_DEC[] = {
        "61517254438303197335701350506590825854257845121325404623337818255145552341515"
};

const byte test_simple_swu_data3_BYTES[] = {
        0x02, 0x6c, 0x68, 0xba, 0x79, 0x9b, 0x95, 0x8d,
        0xa1, 0xdd, 0xec, 0x47, 0xcf, 0x77, 0xb6, 0x1a,
        0x68, 0xe3, 0x27, 0xbb, 0x16, 0xdd, 0x04, 0x6f,
        0x90, 0xfe, 0x2d, 0x7e, 0x46, 0xc7, 0x86, 0x1b,
        0xf9, 0x7a, 0xdb, 0xda, 0x15, 0xef, 0x5c, 0x13,
        0x63, 0xe7, 0x0d, 0x7c, 0xfa, 0x78, 0x24, 0xca,
        0xb9, 0x29, 0x74, 0x96, 0x09, 0x47, 0x15, 0x4d,
        0x34, 0xc4, 0x38, 0xe3, 0xeb, 0xcf, 0xfc, 0xbc,
};

const byte test_simple_swu_x3_DEC[] = {
        "41644486759784367771047752285976210905566569374059610763941558650382638987514"
};

const byte test_simple_swu_y3_DEC[] = {
        "47123545766650584118634862924645280635136629360149764686957339607865971771956"
};

const vsc_data_t test_simple_swu_hash1 = {
        test_simple_swu_hash1_DEC, sizeof(test_simple_swu_hash1_DEC)
};

const vsc_data_t test_simple_swu_x1 = {
        test_simple_swu_x1_DEC, sizeof(test_simple_swu_x1_DEC)
};

const vsc_data_t test_simple_swu_y1 = {
        test_simple_swu_y1_DEC, sizeof(test_simple_swu_y1_DEC)
};

const vsc_data_t test_simple_swu_hash2 = {
        test_simple_swu_hash2_DEC, sizeof(test_simple_swu_hash2_DEC)
};

const vsc_data_t test_simple_swu_x2 = {
        test_simple_swu_x2_DEC, sizeof(test_simple_swu_x2_DEC)
};

const vsc_data_t test_simple_swu_y2 = {
        test_simple_swu_y2_DEC, sizeof(test_simple_swu_y2_DEC)
};

const vsc_data_t test_simple_swu_data3 = {
        test_simple_swu_data3_BYTES, sizeof(test_simple_swu_data3_BYTES)
};

const vsc_data_t test_simple_swu_x3 = {
        test_simple_swu_x3_DEC, sizeof(test_simple_swu_x3_DEC)
};

const vsc_data_t test_simple_swu_y3 = {
        test_simple_swu_y3_DEC, sizeof(test_simple_swu_y3_DEC)
};
