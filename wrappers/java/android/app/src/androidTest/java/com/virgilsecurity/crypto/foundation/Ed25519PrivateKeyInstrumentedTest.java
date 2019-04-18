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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.virgilsecurity.crypto.ratchet.TestData;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class Ed25519PrivateKeyInstrumentedTest {

    private Ed25519PrivateKey privateKey;

    @Before
    public void init() {
        this.privateKey = new Ed25519PrivateKey();
        this.privateKey.setupDefaults();
    }

    @Test
    public void algId() {
        assertEquals(AlgId.ED25519, this.privateKey.algId());
    }

    @Test
    public void keyLen() {
        assertEquals(32, this.privateKey.keyLen());
    }

    @Test
    public void keyBitlen() {
        assertEquals(256, this.privateKey.keyBitlen());
    }

    @Test
    public void generateKey() {
        this.privateKey.generateKey();
        assertEquals(32, this.privateKey.keyLen());
    }

    @Test
    public void sign() {
        byte[] data = TestData.data;

        this.privateKey.generateKey();

        byte[] signature = this.privateKey.signHash(data, this.privateKey.algId());

        assertNotNull(signature);
        assertEquals(64, signature.length);
    }

    @Test
    public void signatureLen() {
        assertEquals(64, this.privateKey.signatureLen());
    }

    @Test
    public void export_import() {
        this.privateKey.generateKey();

        // Export private key
        byte[] exportedKey = this.privateKey.exportPrivateKey();
        assertNotNull(exportedKey);
        assertEquals(this.privateKey.exportedPrivateKeyLen(), exportedKey.length);

        // Import private key
        try (Ed25519PrivateKey importedPrivateKey = new Ed25519PrivateKey()) {
            importedPrivateKey.importPrivateKey(exportedKey);

            // Sing the same data with imported
            byte[] data = TestData.data;
            byte[] signWithGeneratedKey = this.privateKey.signHash(data, this.privateKey.algId());
            byte[] signWithImportedKey = importedPrivateKey.signHash(data, importedPrivateKey.algId());
            assertArrayEquals(signWithGeneratedKey, signWithImportedKey);
        }
    }

    @Test
    public void getCanExportPrivateKey() {
        assertTrue(this.privateKey.getCanExportPrivateKey());
    }

    @Test
    public void getCanImportPrivateKey() {
        assertTrue(this.privateKey.getCanImportPrivateKey());
    }

    @Test
    public void extractPublicKey() {
        this.privateKey.generateKey();
        Ed25519PublicKey publicKey = (Ed25519PublicKey) this.privateKey.extractPublicKey();

        assertNotNull(publicKey);

        byte[] data = TestData.data;
        byte[] signature = this.privateKey.signHash(data, this.privateKey.algId());

        assertTrue(publicKey.verifyHash(data, publicKey.algId(), signature));
    }

    @Test
    public void computeSharedKey() {
        this.privateKey.generateKey();
        Ed25519PublicKey publicKey = (Ed25519PublicKey) this.privateKey.extractPublicKey();

        try (Ed25519PrivateKey secondPrivateKey = new Ed25519PrivateKey()) {
            secondPrivateKey.setupDefaults();
            secondPrivateKey.generateKey();
            Ed25519PublicKey secondPublicKey = (Ed25519PublicKey) secondPrivateKey.extractPublicKey();

            byte[] mySharedKey = this.privateKey.computeSharedKey(secondPublicKey);

            assertNotNull(mySharedKey);
            assertEquals(this.privateKey.sharedKeyLen(), mySharedKey.length);

            byte[] secondSharedKey = secondPrivateKey.computeSharedKey(publicKey);
            assertNotNull(secondSharedKey);

            assertArrayEquals(mySharedKey, secondSharedKey);
        }
    }

}
