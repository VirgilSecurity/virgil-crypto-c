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
public class Aes256CbcInstrumentedTest {

    private Aes256Cbc aes;

    @Before
    public void init() {
        this.aes = new Aes256Cbc();
    }

    @Test
    public void encrypt() {
        this.aes.setKey(TestData.aes256_cbc_key);
        this.aes.setNonce(TestData.aes256_cbc_iv);

        byte[] encryptedData = this.aes.encrypt(TestData.data);

        assertNotNull(encryptedData);
        assertArrayEquals(TestData.aes256_cbc_encrypted_data, encryptedData);
    }

    @Test
    public void encryptWithCipher() {
        byte[] data = TestData.data;

        byte[] encryptedData = null;

        this.aes.setKey(TestData.aes256_cbc_key);
        this.aes.setNonce(TestData.aes256_cbc_iv);
        this.aes.startEncryption();

        encryptedData = ArrayUtils.addAll(encryptedData, this.aes.update(data));
        encryptedData = ArrayUtils.addAll(encryptedData, this.aes.finish());

        assertNotNull(encryptedData);
        assertArrayEquals(TestData.aes256_cbc_encrypted_data, encryptedData);
    }

    @Test
    public void decryptWithCipher() {
        byte[] encryptedData = TestData.aes256_cbc_encrypted_data;
        byte[] decryptedData = null;

        this.aes.setKey(TestData.aes256_cbc_key);
        this.aes.setNonce(TestData.aes256_cbc_iv);
        this.aes.startDecryption();

        decryptedData = ArrayUtils.addAll(decryptedData, this.aes.update(encryptedData));
        decryptedData = ArrayUtils.addAll(decryptedData, this.aes.finish());

        assertNotNull(decryptedData);
        assertArrayEquals(TestData.data, decryptedData);
    }

    @Test
    public void decrypt() {
        byte[] expectedDecryptedData = TestData.data;

        this.aes.setKey(TestData.aes256_cbc_key);
        this.aes.setNonce(TestData.aes256_cbc_iv);

        byte[] decryptedData = this.aes.decrypt(TestData.aes256_cbc_encrypted_data);

        assertNotNull(decryptedData);
        assertArrayEquals(expectedDecryptedData, decryptedData);
    }

    @Test
    public void getNonceLen() {
        assertEquals(16, this.aes.getNonceLen());
    }

    @Test
    public void getKeyLen() {
        assertEquals(32, this.aes.getKeyLen());
    }

    @Test
    public void getKeyBitlen() {
        assertEquals(256, this.aes.getKeyBitlen());
    }

    @Test
    public void getBlockLen() {
        assertEquals(16, this.aes.getBlockLen());
    }

}
