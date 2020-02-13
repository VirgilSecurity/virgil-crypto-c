/*
* Copyright (C) 2015-2020 Virgil Security, Inc.
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
* Class implements UOKMS for client-side.
*/
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

    /* Clear resources. */
    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            PheJNI.INSTANCE.uokmsClient_close(ctx);
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

    /*
    * Setups dependencies with default values.
    */
    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.uokmsClient_setupDefaults(this.cCtx);
    }

    /*
    * Sets client private
    * Call this method before any other methods
    * This function should be called only once
    */
    public void setKeysOneparty(byte[] clientPrivateKey) throws PheException {
        PheJNI.INSTANCE.uokmsClient_setKeysOneparty(this.cCtx, clientPrivateKey);
    }

    /*
    * Sets client private and server public key
    * Call this method before any other methods
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
    * Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
    * of "encryption key len" that can be used for symmetric encryption
    */
    public UokmsClientGenerateEncryptWrapResult generateEncryptWrap(int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateEncryptWrap(this.cCtx, encryptionKeyLen);
    }

    /*
    * Decrypt
    */
    public byte[] decryptOneparty(byte[] wrap, int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_decryptOneparty(this.cCtx, wrap, encryptionKeyLen);
    }

    /*
    * Generates request to decrypt data, this request should be sent to the server.
    * Server response is then passed to "process decrypt response" where encryption key can be decapsulated
    */
    public UokmsClientGenerateDecryptRequestResult generateDecryptRequest(byte[] wrap) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateDecryptRequest(this.cCtx, wrap);
    }

    /*
    * Processed server response, checks server proof and decapsulates encryption key
    */
    public byte[] processDecryptResponse(byte[] wrap, byte[] decryptRequest, byte[] decryptResponse, byte[] deblindFactor, int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_processDecryptResponse(this.cCtx, wrap, decryptRequest, decryptResponse, deblindFactor, encryptionKeyLen);
    }

    /*
    * Rotates client key using given update token obtained from server
    */
    public byte[] rotateKeysOneparty(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_rotateKeysOneparty(this.cCtx, updateToken);
    }

    /*
    * Generates update token for one-party mode
    */
    public byte[] generateUpdateTokenOneparty() throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateUpdateTokenOneparty(this.cCtx);
    }

    /*
    * Rotates client and server keys using given update token obtained from server
    */
    public UokmsClientRotateKeysResult rotateKeys(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_rotateKeys(this.cCtx, updateToken);
    }
}

