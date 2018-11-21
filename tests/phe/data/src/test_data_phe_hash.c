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

#include "test_data_phe_hash.h"

const byte test_phe_hash_data_BYTES[] = {
        0x02, 0x6c, 0x68, 0xba, 0x79, 0x9b, 0x95, 0x8d,
        0xa1, 0xdd, 0xec, 0x47, 0xcf, 0x77, 0xb6, 0x1a,
        0x68, 0xe3, 0x27, 0xbb, 0x16, 0xdd, 0x04, 0x6f,
        0x90, 0xfe, 0x2d, 0x7e, 0x46, 0xc7, 0x86, 0x1b,
        0xf9, 0x7a, 0xdb, 0xda, 0x15, 0xef, 0x5c, 0x13,
        0x63, 0xe7, 0x0d, 0x7c, 0xfa, 0x78, 0x24, 0xca,
        0xb9, 0x29, 0x74, 0x96, 0x09, 0x47, 0x15, 0x4d,
        0x34, 0xc4, 0x38, 0xe3, 0xeb, 0xcf, 0xfc, 0xbc,
};

const byte test_phe_hash_x_DEC[] = {
        "41644486759784367771047752285976210905566569374059610763941558650382638987514"
};

const byte test_phe_hash_y_DEC[] = {
        "47123545766650584118634862924645280635136629360149764686957339607865971771956"
};

const vsc_data_t test_phe_hash_data = {
        test_phe_hash_data_BYTES, sizeof(test_phe_hash_data_BYTES)
};

const vsc_data_t test_phe_hash_x = {
        test_phe_hash_x_DEC, sizeof(test_phe_hash_x_DEC)
};

const vsc_data_t test_phe_hash_y = {
        test_phe_hash_y_DEC, sizeof(test_phe_hash_y_DEC)
};

