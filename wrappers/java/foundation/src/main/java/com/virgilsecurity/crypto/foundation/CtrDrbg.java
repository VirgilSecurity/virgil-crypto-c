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

public class CtrDrbg implements AutoCloseable, Random {

    public long cCtx;

    public CtrDrbg() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.ctrDrbg_new();
    }

    CtrDrbg(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static CtrDrbg getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new CtrDrbg(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.ctrDrbg_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setEntropySource(EntropySource entropySource) {
        FoundationJNI.INSTANCE.ctrDrbg_setEntropySource(this.cCtx, entropySource);
    }

    public byte[] random(int dataLen) throws FoundationException {
        return FoundationJNI.INSTANCE.ctrDrbg_random(this.cCtx, dataLen);
    }

    public void reseed() throws FoundationException {
        FoundationJNI.INSTANCE.ctrDrbg_reseed(this.cCtx);
    }

    public void setupDefaults() throws FoundationException {
        FoundationJNI.INSTANCE.ctrDrbg_setupDefaults(this.cCtx);
    }

    public void enablePredictionResistance() {
        FoundationJNI.INSTANCE.ctrDrbg_enablePredictionResistance(this.cCtx);
    }

    public void setReseedInterval(int interval) {
        FoundationJNI.INSTANCE.ctrDrbg_setReseedInterval(this.cCtx, interval);
    }

    public void setEntropyLen(int len) {
        FoundationJNI.INSTANCE.ctrDrbg_setEntropyLen(this.cCtx, len);
    }

}
