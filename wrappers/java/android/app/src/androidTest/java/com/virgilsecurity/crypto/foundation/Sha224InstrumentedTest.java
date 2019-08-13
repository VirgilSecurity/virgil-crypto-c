/*
 * Copyright (C) 2015-2019 Virgil Security, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * (1) Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * (3) Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

package com.virgilsecurity.crypto.foundation;

import android.support.test.runner.AndroidJUnit4;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.virgilsecurity.crypto.TestData;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(AndroidJUnit4.class)
public class Sha224InstrumentedTest {

    private Sha224 sha224;

    @Before
    public void init() {
        this.sha224 = new Sha224();
    }

    @Test
    public void algId() {
        AlgId algId = this.sha224.algId();
        assertNotNull(algId);
        assertEquals(AlgId.SHA224, algId);
    }

    @Test
    public void getDigestLen() {
        assertEquals(28, this.sha224.getDigestLen());
    }

    @Test
    public void getBlockLen() {
        assertEquals(64, this.sha224.getBlockLen());
    }

    @Test
    public void hash() {
        byte[] expectedHash = TestData.sha224_hash;

        byte[] hash = this.sha224.hash(TestData.data);

        assertNotNull(hash);
        assertEquals(expectedHash.length, hash.length);
        assertArrayEquals(expectedHash, hash);
    }

    @Test
    public void hashStream() {
        byte[] expectedHash = TestData.sha224_hash;

        this.sha224.start();

        int blockLen = this.sha224.getBlockLen();
        for (int startIndex = 0; startIndex < TestData.data.length; startIndex += blockLen) {
            byte[] block = ArrayUtils.subarray(TestData.data, startIndex, startIndex + blockLen);
            this.sha224.update(block);
        }

        byte[] hash = this.sha224.finish();

        assertNotNull(hash);
        assertEquals(expectedHash.length, hash.length);
        assertArrayEquals(expectedHash, hash);
    }

    @Test
    public void produceAlgInfo() {
        AlgInfo algInfo = this.sha224.produceAlgInfo();
        assertNotNull(algInfo);
        assertEquals(AlgId.SHA224, algInfo.algId());
    }

}
