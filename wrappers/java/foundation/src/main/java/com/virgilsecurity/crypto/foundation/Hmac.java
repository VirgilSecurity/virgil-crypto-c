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

public class Hmac implements AutoCloseable, Alg, Mac {

    public long cCtx;

    public Hmac() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.hmac_new();
    }

    Hmac(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static Hmac getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new Hmac(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.hmac_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setHash(Hash hash) {
        FoundationJNI.INSTANCE.hmac_setHash(this.cCtx, hash);
    }

    public AlgId algId() {
        return FoundationJNI.INSTANCE.hmac_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.hmac_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.hmac_restoreAlgInfo(this.cCtx, algInfo);
    }

    public int digestLen() {
        return FoundationJNI.INSTANCE.hmac_digestLen(this.cCtx);
    }

    public byte[] mac(byte[] key, byte[] data) {
        return FoundationJNI.INSTANCE.hmac_mac(this.cCtx, key, data);
    }

    public void start(byte[] key) {
        FoundationJNI.INSTANCE.hmac_start(this.cCtx, key);
    }

    public void update(byte[] data) {
        FoundationJNI.INSTANCE.hmac_update(this.cCtx, data);
    }

    public byte[] finish() {
        return FoundationJNI.INSTANCE.hmac_finish(this.cCtx);
    }

    public void reset() {
        FoundationJNI.INSTANCE.hmac_reset(this.cCtx);
    }

}
