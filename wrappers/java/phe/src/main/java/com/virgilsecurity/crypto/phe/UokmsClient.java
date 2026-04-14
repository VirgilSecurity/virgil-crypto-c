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

public class UokmsClient implements AutoCloseable {

    public long cCtx;

    public UokmsClient() {
        super();
        this.cCtx = PheJNI.INSTANCE.uokmsClient_new();
    }

    package UokmsClient(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public UokmsClient getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new UokmsClient(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            PheJNI.INSTANCE.uokmsClient_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        PheJNI.INSTANCE.uokmsClient_setRandom(this.cCtx, random);
    }

    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.uokmsClient_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.uokmsClient_setupDefaults(this.cCtx);
    }

    public void setKeysOneparty(byte[] clientPrivateKey) throws PheException {
        PheJNI.INSTANCE.uokmsClient_setKeysOneparty(this.cCtx, clientPrivateKey);
    }

    public void setKeys(byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException {
        PheJNI.INSTANCE.uokmsClient_setKeys(this.cCtx, clientPrivateKey, serverPublicKey);
    }

    public byte[] generateClientPrivateKey() throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateClientPrivateKey(this.cCtx);
    }

    public UokmsClientGenerateEncryptWrapResult generateEncryptWrap(int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateEncryptWrap(this.cCtx, encryptionKeyLen);
    }

    public byte[] decryptOneparty(byte[] wrap, int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_decryptOneparty(this.cCtx, wrap, encryptionKeyLen);
    }

    public UokmsClientGenerateDecryptRequestResult generateDecryptRequest(byte[] wrap) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateDecryptRequest(this.cCtx, wrap);
    }

    public byte[] processDecryptResponse(byte[] wrap, byte[] decryptRequest, byte[] decryptResponse, byte[] deblindFactor, int encryptionKeyLen) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_processDecryptResponse(this.cCtx, wrap, decryptRequest, decryptResponse, deblindFactor, encryptionKeyLen);
    }

    public byte[] rotateKeysOneparty(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_rotateKeysOneparty(this.cCtx, updateToken);
    }

    public byte[] generateUpdateTokenOneparty() throws PheException {
        return PheJNI.INSTANCE.uokmsClient_generateUpdateTokenOneparty(this.cCtx);
    }

    public UokmsClientRotateKeysResult rotateKeys(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.uokmsClient_rotateKeys(this.cCtx, updateToken);
    }

}
