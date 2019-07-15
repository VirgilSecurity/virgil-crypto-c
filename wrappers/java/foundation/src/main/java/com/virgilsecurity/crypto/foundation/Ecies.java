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

/*
* Virgil implementation of the ECIES algorithm.
*/
public class Ecies implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public Ecies() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.ecies_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static Ecies getInstance(long cCtx) {
        Ecies newInstance = new Ecies();
        newInstance.cCtx = cCtx;
        return newInstance;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.ecies_close(this.cCtx);
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.ecies_setRandom(this.cCtx, random);
    }

    public void setCipher(Cipher cipher) {
        FoundationJNI.INSTANCE.ecies_setCipher(this.cCtx, cipher);
    }

    public void setMac(Mac mac) {
        FoundationJNI.INSTANCE.ecies_setMac(this.cCtx, mac);
    }

    public void setKdf(Kdf kdf) {
        FoundationJNI.INSTANCE.ecies_setKdf(this.cCtx, kdf);
    }

    /*
    * Set ephemeral key that used for data encryption.
    * Public and ephemeral keys should belong to the same curve.
    * This dependency is optional.
    */
    public void setEphemeralKey(PrivateKey ephemeralKey) {
        FoundationJNI.INSTANCE.ecies_setEphemeralKey(this.cCtx, ephemeralKey);
    }

    /*
    * Set weak reference to the key algorithm.
    * Key algorithm MUST support shared key computation as well.
    */
    public void setKeyAlg(KeyAlg keyAlg) {
        FoundationJNI.INSTANCE.ecies_setKeyAlg(this.cCtx, keyAlg);
    }

    /*
    * Release weak reference to the key algorithm.
    */
    public void releaseKeyAlg() {
        FoundationJNI.INSTANCE.ecies_releaseKeyAlg(this.cCtx);
    }

    /*
    * Setup predefined values to the uninitialized class dependencies.
    */
    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.ecies_setupDefaults(this.cCtx);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
    */
    public int encryptedLen(PublicKey publicKey, int dataLen) {
        return FoundationJNI.INSTANCE.ecies_encryptedLen(this.cCtx, publicKey, dataLen);
    }

    /*
    * Encrypt data with a given public key.
    */
    public byte[] encrypt(PublicKey publicKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.ecies_encrypt(this.cCtx, publicKey, data);
    }

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    public int decryptedLen(PrivateKey privateKey, int dataLen) {
        return FoundationJNI.INSTANCE.ecies_decryptedLen(this.cCtx, privateKey, dataLen);
    }

    /*
    * Decrypt given data.
    */
    public byte[] decrypt(PrivateKey privateKey, byte[] data) throws FoundationException {
        return FoundationJNI.INSTANCE.ecies_decrypt(this.cCtx, privateKey, data);
    }
}

