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

public class PheClient implements AutoCloseable {

    public long cCtx;

    public PheClient() {
        super();
        this.cCtx = PheJNI.INSTANCE.pheClient_new();
    }

    package PheClient(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public PheClient getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new PheClient(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            PheJNI.INSTANCE.pheClient_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        PheJNI.INSTANCE.pheClient_setRandom(this.cCtx, random);
    }

    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.pheClient_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.pheClient_setupDefaults(this.cCtx);
    }

    public void setKeys(byte[] clientPrivateKey, byte[] serverPublicKey) throws PheException {
        PheJNI.INSTANCE.pheClient_setKeys(this.cCtx, clientPrivateKey, serverPublicKey);
    }

    public byte[] generateClientPrivateKey() throws PheException {
        return PheJNI.INSTANCE.pheClient_generateClientPrivateKey(this.cCtx);
    }

    public int enrollmentRecordLen() {
        return PheJNI.INSTANCE.pheClient_enrollmentRecordLen(this.cCtx);
    }

    public PheClientEnrollAccountResult enrollAccount(byte[] enrollmentResponse, byte[] password) throws PheException {
        return PheJNI.INSTANCE.pheClient_enrollAccount(this.cCtx, enrollmentResponse, password);
    }

    public int verifyPasswordRequestLen() {
        return PheJNI.INSTANCE.pheClient_verifyPasswordRequestLen(this.cCtx);
    }

    public byte[] createVerifyPasswordRequest(byte[] password, byte[] enrollmentRecord) throws PheException {
        return PheJNI.INSTANCE.pheClient_createVerifyPasswordRequest(this.cCtx, password, enrollmentRecord);
    }

    public byte[] checkResponseAndDecrypt(byte[] password, byte[] enrollmentRecord, byte[] verifyPasswordResponse) throws PheException {
        return PheJNI.INSTANCE.pheClient_checkResponseAndDecrypt(this.cCtx, password, enrollmentRecord, verifyPasswordResponse);
    }

    public PheClientRotateKeysResult rotateKeys(byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.pheClient_rotateKeys(this.cCtx, updateToken);
    }

    public byte[] updateEnrollmentRecord(byte[] enrollmentRecord, byte[] updateToken) throws PheException {
        return PheJNI.INSTANCE.pheClient_updateEnrollmentRecord(this.cCtx, enrollmentRecord, updateToken);
    }

}
