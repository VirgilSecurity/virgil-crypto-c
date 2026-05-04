/*
* Copyright (C) 2015-2026 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*     (3) Neither the name of the copyright holder nor the names of its
*     contributors may be used to endorse or promote products derived from
*     this software without specific prior written permission.
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

public class BrainkeyClient implements AutoCloseable {

    public long cCtx;

    public BrainkeyClient() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.brainkeyClient_new();
    }

    BrainkeyClient(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static BrainkeyClient getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new BrainkeyClient(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.brainkeyClient_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.brainkeyClient_setRandom(this.cCtx, random);
    }

    public void setOperationRandom(Random operationRandom) {
        FoundationJNI.INSTANCE.brainkeyClient_setOperationRandom(this.cCtx, operationRandom);
    }

    public int getPointLen() {
        return 65;
    }

    public int getMpiLen() {
        return 32;
    }

    public int getSeedLen() {
        return 32;
    }

    public int getMaxPasswordLen() {
        return 128;
    }

    public int getMaxKeyNameLen() {
        return 128;
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.brainkeyClient_setupDefaults(this.cCtx);
    }

    public BrainkeyClientBlindResult blind(byte[] password) throws FoundationException {
        return FoundationJNI.INSTANCE.brainkeyClient_blind(this.cCtx, password);
    }

    public byte[] deblind(byte[] password, byte[] hardenedPoint, byte[] deblindFactor, byte[] keyName) throws FoundationException {
        return FoundationJNI.INSTANCE.brainkeyClient_deblind(this.cCtx, password, hardenedPoint, deblindFactor, keyName);
    }

    public bool verify(byte[] blindedPoint, byte[] hardenedPoint, byte[] serverPublicKey, byte[] proofValueC, byte[] proofValueS) throws FoundationException {
        return FoundationJNI.INSTANCE.brainkeyClient_verify(this.cCtx, blindedPoint, hardenedPoint, serverPublicKey, proofValueC, proofValueS);
    }

}
