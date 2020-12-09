<?php
/**
 * Copyright (C) 2015-2020 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\CryptoWrapperTests\Foundation;

use Virgil\CryptoWrapper\Foundation\Binary;

class BinaryTest extends \PHPUnit\Framework\TestCase
{
    const BINARY_DATA = "2saYMwjfh6ZKmpzS8Gn71+Wl/DnURsjGIWcAAshaHnH32RDhpZSem6l5HhvLG0TZ5F7b1cDzB9Bk4XomxINviHozt3KZ3DmBKZitQAIU9/6/qCnJzuxbHgOteIFsE65WfOEmrVbK8sRZuVvp2MYbG/5FoCb6hTlHTgQHv5xafd0b8J/aAzGKm2r4Ug9kUQSwc1PgnzSazXh5z4Z1RYyMGPel/yv6ZfUWs5gDKRJAImuvzGL64fUCmxz9Fifua2G5t9DTpErTUIcuZgtuIqU9UoogJIxbkftxtGrBxzBMWveCIdsUNlqiT/ileOAofwiPn9V91Wybhk8gXSwIOV2B5YeZhNmzhZXK1JZKVIpvSIrNPuDJ11NdSCSJ0hpKSwuZdQZAIu6Mm3apgVFJBcEQNbc/Xh3PtTDx6asDqDktmywDj7E6xCUZZP9Z0A0pvsbzRSE9+X7y0V57sy8r8MKlVWlPGu5JJ4zLh+6BSthX6pshdvrNgLv/g0p3PgLsA47S5QWIb0L80sSQqePKyxvdWjsPepVlXaIOqgD2Db/9VHE4z51SquX/U5Lh5w4NeyEpRgBOvDKqgJVTY7HgjgL3zybzBwkxDWJjp7lx9X5gzKI4tEoV4LO3PuEl6h6TJ9BA+sDsCLhnrs0NkjyZURcju84R2a7cVn8GVTpW45wTom7/e+w41mdyTqUIEUyOgZ/GBbC4HYaUBXWShpyuih0VdQhYgn5WgDoKd4lpdpGe1MOiGiTVsr1q4eH84ajTus4j6YXYU7d2FmMsb+gDiWHtoKwmiXAqbShXbUSxwQE+dwv7T2Eaq4Vl+ZKzQe/617947FZHZylSbdLI8f6IMeVIxZxGx3eYTxQMHDB6cjugrmd0UCZ/4co3z2RPTHKVOAKfrXwGaxqhtuZgbp5a+a/SpRVfdnb2TjkWG7YqkfK4VXYS1MDvfwMnr5cIUwCyaicJ5wkNywKqzEmodaHEI94wGDZaH/ZJH5avIJrgcDsIs+/Ft483DwaJ9CxNOLWUZXTphLTSLbDuMy39P51lO0vl1s5jvnwgxjvCqnOo/8fw9/fvnASjHcDc9lSp1cGth6aS5mGwUKgwUxuKMHZk0/Py02tuTHSwCHQa77eXcWL50CsyMzXaEOoDkhoE9drg8yS7ccH4+LwG15q9sACufWoO66Bqy/I2P7NvCGB49KwVV7B/GECHRTSRk0/88N31KVT6XaHfhek/cDjp77ISCfwQE5acKqqJibzyW3dHhBZSd1Rce0XIbqmFKbZxhpJc9posuulG/3SPt9Q9UwbvAF+Tb9a7HK/+oG6PSh7GMiB/p/B263skKkKbmHGGA6UnFT0sxGmUAUU+uE7loa2sYQo+4Q==";
    const BINARY_DATA_LEN = 1024;
    const BINARY_HEX = "dac6983308df87a64a9a9cd2f069fbd7e5a5fc39d446c8c621670002c85a1e71f7d910e1a5949e9ba9791e1bcb1b44d9e45edbd5c0f307d064e17a26c4836f887a33b77299dc39812998ad400214f7febfa829c9ceec5b1e03ad78816c13ae567ce126ad56caf2c459b95be9d8c61b1bfe45a026fa8539474e0407bf9c5a7ddd1bf09fda03318a9b6af8520f645104b07353e09f349acd7879cf8675458c8c18f7a5ff2bfa65f516b39803291240226bafcc62fae1f5029b1cfd1627ee6b61b9b7d0d3a44ad350872e660b6e22a53d528a20248c5b91fb71b46ac1c7304c5af78221db14365aa24ff8a578e0287f088f9fd57dd56c9b864f205d2c08395d81e5879984d9b38595cad4964a548a6f488acd3ee0c9d7535d482489d21a4a4b0b9975064022ee8c9b76a981514905c11035b73f5e1dcfb530f1e9ab03a8392d9b2c038fb13ac4251964ff59d00d29bec6f345213df97ef2d15e7bb32f2bf0c2a555694f1aee49278ccb87ee814ad857ea9b2176facd80bbff834a773e02ec038ed2e505886f42fcd2c490a9e3cacb1bdd5a3b0f7a95655da20eaa00f60dbffd547138cf9d52aae5ff5392e1e70e0d7b212946004ebc32aa80955363b1e08e02f7cf26f30709310d6263a7b971f57e60cca238b44a15e0b3b73ee125ea1e9327d040fac0ec08b867aecd0d923c99511723bbce11d9aedc567f06553a56e39c13a26eff7bec38d667724ea508114c8e819fc605b0b81d8694057592869cae8a1d15750858827e56803a0a77896976919ed4c3a21a24d5b2bd6ae1e1fce1a8d3bace23e985d853b77616632c6fe8038961eda0ac2689702a6d28576d44b1c1013e770bfb4f611aab8565f992b341effad7bf78ec56476729526dd2c8f1fe8831e548c59c46c777984f140c1c307a723ba0ae677450267fe1ca37cf644f4c729538029fad7c066b1aa1b6e6606e9e5af9afd2a5155f7676f64e39161bb62a91f2b8557612d4c0ef7f0327af97085300b26a2709e7090dcb02aacc49a875a1c423de3018365a1ff6491f96af209ae0703b08b3efc5b78f370f0689f42c4d38b5946574e984b4d22db0ee332dfd3f9d653b4be5d6ce63be7c20c63bc2aa73a8ffc7f0f7f7ef9c04a31dc0dcf654a9d5c1ad87a692e661b050a830531b8a307664d3f3f2d36b6e4c74b008741aefb7977162f9d02b323335da10ea03921a04f5dae0f324bb71c1f8f8bc06d79abdb000ae7d6a0eeba06acbf2363fb36f086078f4ac1557b07f184087453491934ffcf0ddf52954fa5da1df85e93f7038e9efb21209fc1013969c2aaa8989bcf25b774784165277545c7b45c86ea98529b67186925cf69a2cbae946ff748fb7d43d5306ef005f936fd6bb1caffea06e8f4a1ec632207fa7f076eb7b242a429b98718603a527153d2cc4699401453eb84ee5a1adac610a3ee1";
    const BINARY_HEX_LEN = 2048;

    public function test_Binary_fromHex()
    {
        $res = Binary::fromHex(BinaryTest::BINARY_HEX);
        $this->assertEquals(base64_decode(BinaryTest::BINARY_DATA), $res);
    }

    public function test_Binary_fromHexLen()
    {
        $res = Binary::fromHexLen(strlen(BinaryTest::BINARY_HEX));
        $this->assertEquals(BinaryTest::BINARY_DATA_LEN, $res);
    }

    public function test_Binary_toHex()
    {
        $res = Binary::toHex(base64_decode(BinaryTest::BINARY_DATA));
        $this->assertEquals(BinaryTest::BINARY_HEX, $res);
    }

    public function test_Binary_toHexLen()
    {
        $res = Binary::toHexLen(strlen(base64_decode(BinaryTest::BINARY_DATA)));
        $this->assertEquals(BinaryTest::BINARY_HEX_LEN, $res);
    }

}
