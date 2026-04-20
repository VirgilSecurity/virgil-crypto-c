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

public class PheServer implements AutoCloseable {

    public long cCtx;

    public PheServer() {
        super();
        this.cCtx = PheJNI.INSTANCE.pheServer_new();
    }

    PheServer(PheContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static PheServer getInstance(long cCtx) {
        PheContextHolder ctxHolder = new PheContextHolder(cCtx);
        return new PheServer(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            PheJNI.INSTANCE.pheServer_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        PheJNI.INSTANCE.pheServer_setRandom(this.cCtx, random);
    }

    public void setOperationRandom(Random operationRandom) {
        PheJNI.INSTANCE.pheServer_setOperationRandom(this.cCtx, operationRandom);
    }

    public void setupDefaults() throws PheException {
        PheJNI.INSTANCE.pheServer_setupDefaults(this.cCtx);
    }

    public PheServerGenerateServerKeyPairResult generateServerKeyPair() throws PheException {
        return PheJNI.INSTANCE.pheServer_generateServerKeyPair(this.cCtx);
    }

    public int enrollmentResponseLen() {
        return PheJNI.INSTANCE.pheServer_enrollmentResponseLen(this.cCtx);
    }

    public byte[] getEnrollment(byte[] serverPrivateKey, byte[] serverPublicKey) throws PheException {
        return PheJNI.INSTANCE.pheServer_getEnrollment(this.cCtx, serverPrivateKey, serverPublicKey);
    }

    public int verifyPasswordResponseLen() {
        return PheJNI.INSTANCE.pheServer_verifyPasswordResponseLen(this.cCtx);
    }

    public byte[] verifyPassword(byte[] serverPrivateKey, byte[] serverPublicKey, byte[] verifyPasswordRequest) throws PheException {
        return PheJNI.INSTANCE.pheServer_verifyPassword(this.cCtx, serverPrivateKey, serverPublicKey, verifyPasswordRequest);
    }

    public int updateTokenLen() {
        return PheJNI.INSTANCE.pheServer_updateTokenLen(this.cCtx);
    }

    public PheServerRotateKeysResult rotateKeys(byte[] serverPrivateKey) throws PheException {
        return PheJNI.INSTANCE.pheServer_rotateKeys(this.cCtx, serverPrivateKey);
    }

}
