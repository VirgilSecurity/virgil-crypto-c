/*
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

package com.virgilsecurity.crypto.phe;

import com.virgilsecurity.crypto.foundation.*;

/*
* Class for encryption using PHE account key
* This class is thread-safe.
*/
public class PheCipher implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public PheCipher() {
        super();
        this.cCtx = PheJNI.INSTANCE.pheCipher_new();
    }

    /* Wrap underlying C context. */
    PheCipher(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static PheCipher getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new PheCipher(ctxHolder);
    }

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            PheJNI.INSTANCE.pheCipher_close(ctx);
        }
    }

    /* Close resource. */
    public void close() {
        clearResources();
    }

    /* Finalize resource. */
    protected void finalize() throws Throwable {
        clearResources();
    }

    /*
    * Random used for salt generation
    */
    public void setRandom(Random random) {
        PheJNI.INSTANCE.pheCipher_setRandom(this.cCtx, random);
    }

    /*
    * Setups dependencies with default values.
    */
    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.pheCipher_setupDefaults(this.cCtx);
    }

    /*
    * Returns buffer capacity needed to fit cipher text
    */
    public int encryptLen(int plainTextLen) {
        return PheJNI.INSTANCE.pheCipher_encryptLen(this.cCtx, plainTextLen);
    }

    /*
    * Returns buffer capacity needed to fit plain text
    */
    public int decryptLen(int cipherTextLen) {
        return PheJNI.INSTANCE.pheCipher_decryptLen(this.cCtx, cipherTextLen);
    }

    /*
    * Encrypts data using account key
    */
    public byte[] encrypt(byte[] plainText, byte[] accountKey) throws PheException {
        return PheJNI.INSTANCE.pheCipher_encrypt(this.cCtx, plainText, accountKey);
    }

    /*
    * Decrypts data using account key
    */
    public byte[] decrypt(byte[] cipherText, byte[] accountKey) throws PheException {
        return PheJNI.INSTANCE.pheCipher_decrypt(this.cCtx, cipherText, accountKey);
    }

    /*
    * Encrypts data (and authenticates additional data) using account key
    */
    public byte[] authEncrypt(byte[] plainText, byte[] additionalData, byte[] accountKey) throws PheException {
        return PheJNI.INSTANCE.pheCipher_authEncrypt(this.cCtx, plainText, additionalData, accountKey);
    }

    /*
    * Decrypts data (and verifies additional data) using account key
    */
    public byte[] authDecrypt(byte[] cipherText, byte[] additionalData, byte[] accountKey) throws PheException {
        return PheJNI.INSTANCE.pheCipher_authDecrypt(this.cCtx, cipherText, additionalData, accountKey);
    }
}

