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

package com.virgilsecurity.crypto.phe;

import com.virgilsecurity.crypto.foundation.*;

public class UokmsClient implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public UokmsClient() {
        super();
        this.cCtx = PheJNI.INSTANCE.uokmsClient_new();
    }

    /* Wrap underlying C context. */
    UokmsClient(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static UokmsClient getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new UokmsClient(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        PheJNI.INSTANCE.uokmsClient_close(this.cCtx);
    }

    /*
    * Random used for key generation, proofs, etc.
    */
    public void setRandom(Random random) {
        PheJNI.INSTANCE.uokmsClient_setRandom(this.cCtx, random);
    }

    /*
    * Random used for crypto operations to make them const-time
    */
    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.uokmsClient_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.uokmsClient_setupDefaults(this.cCtx);
    }

    /*
    * Sets client private and server public key
    * Call this method before any other methods except `update enrollment record` and `generate client private key`
    * This function should be called only once
    */
    public void setKeys(byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException {
        PheJNI.INSTANCE.uokmsClient_setKeys(this.cCtx, clientPrivateKey, serverPublicKey);
    }

    /*
    * Generates client private key
    */
    public byte[] generateClientPrivateKey() throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateClientPrivateKey(this.cCtx);
    }

    /*
    * Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
    * a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
    * Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
    */
    public UokmsClientGenerateEncryptWrapResult generateEncryptWrap(int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateEncryptWrap(this.cCtx, encryptionKeyLen);
    }

    /*
    * Decrypts data (and verifies additional data) using account key
    */
    public UokmsClientGenerateDecryptRequestResult generateDecryptRequest(byte[] wrap) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateDecryptRequest(this.cCtx, wrap);
    }

    /*
    * Decrypts data (and verifies additional data) using account key
    */
    public byte[] processDecryptResponse(byte[] wrap, byte[] decryptResponse, byte[] deblindFactor, int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_processDecryptResponse(this.cCtx, wrap, decryptResponse, deblindFactor, encryptionKeyLen);
    }

    /*
    * Updates client's private key and server's public key using server's update token
    * Use output values to instantiate new client instance with new keys
    */
    public UokmsClientRotateKeysResult rotateKeys(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_rotateKeys(this.cCtx, updateToken);
    }
}

