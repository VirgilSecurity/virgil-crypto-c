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

#include "test_data_phe_hash.h"

const byte test_phe_hash_ns1_BYTES[] = {
        0x8e, 0x48, 0xac, 0x4b, 0x4a, 0x0c, 0x3f, 0x87,
        0x83, 0x69, 0x6f, 0x5d, 0x1f, 0x77, 0xd4, 0x25,
        0x64, 0x84, 0xd5, 0xb0, 0x7f, 0xd3, 0x8a, 0xf6,
        0xb2, 0xbf, 0x2d, 0x7b, 0x34, 0x57, 0x8a, 0x24,
};

const char test_phe_hash_hs0_x_DEC[] = {
        "25300858746488398178355367558777222618482687866522608982770829435057272700048"
};

const char test_phe_hash_hs0_y_DEC[] = {
        "110446173948945874058011275277660983270153244227256872727234408438424462761061"
};

const byte test_phe_hash_ns2_BYTES[] = {
        0x04, 0x60, 0x41, 0x90, 0xea, 0xe3, 0x03, 0x48,
        0xc4, 0x67, 0xa2, 0x56, 0xaa, 0x20, 0xf0, 0xe1,
        0x22, 0xfd, 0x4c, 0x54, 0xb0, 0x2a, 0x03, 0x26,
        0x84, 0xf1, 0x22, 0x11, 0xfc, 0x9a, 0x8e, 0xe3,
};

const char test_phe_hash_hs1_x_DEC[] = {
        "17908376941582875772307252089828253420307082915473361881522058301944387204152"
};

const char test_phe_hash_hs1_y_DEC[] = {
        "33408333837140987002065754540391028444871058307081963101365044681462597430369"
};

const byte test_phe_hash_nc1_BYTES[] = {
        0xdb, 0x59, 0x4e, 0x9a, 0x53, 0xeb, 0x35, 0x39,
        0x84, 0x63, 0x67, 0xf1, 0x4c, 0x15, 0xa1, 0x9b,
        0x4b, 0xee, 0x1d, 0x27, 0x13, 0xf3, 0xaa, 0xb5,
        0x3b, 0x11, 0x72, 0xd6, 0x02, 0x51, 0x63, 0x36,
};

const byte test_phe_hash_hc0_pwd_BYTES[] = {
        0x5a, 0xf6, 0xf9, 0x9a, 0xc2, 0x0d, 0x0d, 0x54,
        0x52, 0xa2,
};

const byte test_phe_hash_nc2_BYTES[] = {
        0x91, 0xd2, 0x04, 0x0b, 0x8e, 0x52, 0x7e, 0x8a,
        0xe3, 0x40, 0xf6, 0x89, 0xda, 0x01, 0x7c, 0xd6,
        0x1e, 0x20, 0x25, 0xd0, 0xbc, 0xc4, 0xd1, 0x24,
        0x92, 0x5c, 0x87, 0xc3, 0xe9, 0x59, 0xc7, 0x54,
};

const byte test_phe_hash_hc1_pwd_BYTES[] = {
        0xb8, 0xce, 0xc3, 0xde, 0xfd, 0xfc, 0x80, 0x3c, 0x18,
        0x5d,
};

const char test_phe_hash_hc0_x_DEC[] = {
        "71581924212971445159021410682851786422010928474259399013091051697427945751880"
};

const char test_phe_hash_hc0_y_DEC[] = {
        "82599985433400511569162075253342037148256984798119669265653399740244502620726"
};

const char test_phe_hash_hc1_x_DEC[] = {
        "49501362177553120463897295920682327704465381738906627606535872853621035764254"
};

const char test_phe_hash_hc1_y_DEC[] = {
        "47270509952559745766619070899406283523267398868407265017727132307696482921539"
};

const vsc_data_t test_phe_hash_ns1 = {
        test_phe_hash_ns1_BYTES, sizeof(test_phe_hash_ns1_BYTES)
};

const vsc_data_t test_phe_hash_ns2 = {
        test_phe_hash_ns2_BYTES, sizeof(test_phe_hash_ns2_BYTES)
};

const vsc_data_t test_phe_hash_nc1 = {
        test_phe_hash_nc1_BYTES, sizeof(test_phe_hash_nc1_BYTES)
};

const vsc_data_t test_phe_hash_nc2 = {
        test_phe_hash_nc2_BYTES, sizeof(test_phe_hash_nc2_BYTES)
};

const vsc_data_t test_phe_hash_hc0_pwd = {
        test_phe_hash_hc0_pwd_BYTES, sizeof(test_phe_hash_hc0_pwd_BYTES)
};

const vsc_data_t test_phe_hash_hc1_pwd = {
        test_phe_hash_hc1_pwd_BYTES, sizeof(test_phe_hash_hc1_pwd_BYTES)
};

const byte test_phe_hash_z_s_pub_BYTES[] = {
        0x04, 0x21, 0xc3, 0x71, 0x95, 0x74, 0xaf, 0xce,
        0xc6, 0x5e, 0x35, 0xbd, 0x77, 0x5a, 0x5b, 0xe3,
        0x6c, 0x77, 0xc0, 0xbe, 0x45, 0x01, 0xf5, 0xd7,
        0x0f, 0xf0, 0x70, 0xd5, 0x1a, 0x89, 0x3a, 0xd8,
        0xe0, 0x0c, 0xe6, 0xb8, 0x9b, 0x17, 0x88, 0xe6,
        0xc1, 0x27, 0xa0, 0xe1, 0x25, 0xd9, 0xde, 0x6a,
        0x71, 0x16, 0x46, 0xa0, 0x38, 0x0f, 0xc4, 0xe9,
        0x5a, 0x74, 0xe5, 0x2c, 0x89, 0xf1, 0x12, 0x2a,
        0x7c,
};

const char test_phe_hash_z_s_c0_x_DEC[] = {
        "97803661066250274657510595696566855164534492744724548093309723513248461995097"
};

const char test_phe_hash_z_s_c0_y_DEC[] = {
        "32563640650805051226489658838020042684659728733816530715089727234214066735908"
};

const char test_phe_hash_z_s_c1_x_DEC[] = {
        "83901588226167680046300869772314554609808129217097458603677198943293551162597"
};

const char test_phe_hash_z_s_c1_y_DEC[] = {
        "69578797673242144759724361924884259223786981560985539034793627438888366836078"
};

const char test_phe_hash_z_s_term1_x_DEC[] = {
        "34051691470374495568913340263568595354597873005782528499014802063444122859583"
};

const char test_phe_hash_z_s_term1_y_DEC[] = {
        "55902370943165854960816059167184401667567213725158022607170263924097403943290"
};

const char test_phe_hash_z_s_term2_x_DEC[] = {
        "101861885104337123215820986653465602199317278936192518417111183141791463240617"
};

const char test_phe_hash_z_s_term2_y_DEC[] = {
        "40785451420258280256125533532563267231769863378114083364571107590767796025737"
};

const char test_phe_hash_z_s_term3_x_DEC[] = {
        "79689595215343344259388135277552904427007069090288122793121340067386243614518"
};

const char test_phe_hash_z_s_term3_y_DEC[] = {
        "63043970895569149637126206639504503565389755448934804609068720159153015056302"
};

const char test_phe_hash_z_s_challenge_DEC[] = {
        "93919747365284119397236447539917482315419780885577135068398876525953972539838"
};

const vsc_data_t test_phe_hash_z_s_pub = {
        test_phe_hash_z_s_pub_BYTES, sizeof(test_phe_hash_z_s_pub_BYTES)
};

const byte test_phe_hash_z_f_pub_BYTES[] = {
        0x04, 0x39, 0x01, 0x9b, 0x9e, 0x2f, 0x1b, 0xae,
        0x60, 0x65, 0xcd, 0x9b, 0x85, 0x94, 0xfe, 0xa6,
        0xe3, 0x5a, 0x9a, 0xfd, 0xd3, 0x15, 0x96, 0xca,
        0xd8, 0xf8, 0xa4, 0xb1, 0xbd, 0xcd, 0x9b, 0x24,
        0x40, 0x5b, 0x8b, 0x13, 0x23, 0xf2, 0xdd, 0x6b,
        0x1b, 0x1d, 0x3f, 0x57, 0x5d, 0x00, 0xf4, 0xa8,
        0x5f, 0xb8, 0x67, 0x90, 0x69, 0x74, 0xea, 0x16,
        0x4b, 0x41, 0x9e, 0x93, 0x66, 0x47, 0xd8, 0xfb,
        0x7b,
};

const char test_phe_hash_z_f_c0_x_DEC[] = {
        "66305582120524875023859689648303664817335268054431490163250455437389177295478"
};

const char test_phe_hash_z_f_c0_y_DEC[] = {
        "19615011428787373705295950431517815162915845805720956004550495681707511034851"
};

const char test_phe_hash_z_f_c1_x_DEC[] = {
        "11237049376971579382843942757546874380042467137583453135179008882019225463739"
};

const char test_phe_hash_z_f_c1_y_DEC[] = {
        "80961525191994723690800208523971748057046695876178833586656397502847317233228"
};

const char test_phe_hash_z_f_term1_x_DEC[] = {
        "39244241269455735193598520026736537476566784866134072628798326598844377151651"
};

const char test_phe_hash_z_f_term1_y_DEC[] = {
        "10612278657611837393693400625940452527356993857624739575347941960949401758261"
};

const char test_phe_hash_z_f_term2_x_DEC[] = {
        "108016526337105983792792579967716341976396349948643843073602635679441433077833"
};

const char test_phe_hash_z_f_term2_y_DEC[] = {
        "90379537067318020066230942533439624193620174277378193732900885672181004096656"
};

const char test_phe_hash_z_f_term3_x_DEC[] = {
        "36913295823787819500630010367019659122715720420780370192192548665300728488299"
};

const char test_phe_hash_z_f_term3_y_DEC[] = {
        "36547572032269541322937508337036635249923361457001752921238955135105574250650"
};

const char test_phe_hash_z_f_term4_x_DEC[] = {
        "49166285642990312777312778351013119878896537776050488997315166935690363463787"
};

const char test_phe_hash_z_f_term4_y_DEC[] = {
        "66983832439067043864623691503721372978034854603698954939248898067109763920732"
};

const char test_phe_hash_z_f_challenge_DEC[] = {
        "98801234524135497507777343590157351416109876307242902372535142932873423904771"
};

const vsc_data_t test_phe_hash_z_f_pub = {
        test_phe_hash_z_f_pub_BYTES, sizeof(test_phe_hash_z_f_pub_BYTES)
};
