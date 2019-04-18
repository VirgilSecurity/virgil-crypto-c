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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class Ed25519PublicKeyInstrumentedTest {

    private Ed25519PublicKey publicKey;

    @Before
    public void init() {
        this.publicKey = new Ed25519PublicKey();
    }

    @Test
    public void alg() {
        assertEquals(AlgId.ED25519, this.publicKey.algId());
    }

    @Test
    public void keyLen() {
        assertEquals(32, this.publicKey.keyLen());
    }

    @Test
    public void keyBitlen() {
        assertEquals(256, this.publicKey.keyBitlen());
    }

    @Test
    public void verify() {
        byte[] data = TestData.data;
        byte[] signature = TestData.ed25519_signature;
        byte[] wrongSignature = TestData.ed25519_wrong_signature;

        this.publicKey.importPublicKey(TestData.ed25519_public_key);

        assertTrue(this.publicKey.verifyHash(data, this.publicKey.algId(), signature));
        assertFalse(this.publicKey.verifyHash(data, this.publicKey.algId(), wrongSignature));
    }

    @Test
    public void export_import() {
        try (Ed25519PrivateKey privateKey = new Ed25519PrivateKey()) {
            privateKey.setupDefaults();
            privateKey.generateKey();
            byte[] keyData = privateKey.extractPublicKey().exportPublicKey();

            this.publicKey.importPublicKey(keyData);
        }

        // Export public key
        byte[] exportedKey = this.publicKey.exportPublicKey();
        assertNotNull(exportedKey);
        assertEquals(this.publicKey.exportedPublicKeyLen(), exportedKey.length);

        // Import public key
        try (Ed25519PublicKey importedPublicKey = new Ed25519PublicKey()) {
            importedPublicKey.importPublicKey(exportedKey);
        }
    }

    @Test
    public void getCanExportPublicKey() {
        assertTrue(this.publicKey.getCanExportPublicKey());
    }

    @Test
    public void getCanImportPublicKey() {
        assertTrue(this.publicKey.getCanImportPublicKey());
    }

}
