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

public class RandomPadding implements AutoCloseable, Alg, Padding {

    public long cCtx;

    public RandomPadding() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.randomPadding_new();
    }

    RandomPadding(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public static RandomPadding getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new RandomPadding(ctxHolder);
    }

    private void clearResources() {
        long ctx = this.cCtx;
        if (this.cCtx > 0) {
            this.cCtx = 0;
            FoundationJNI.INSTANCE.randomPadding_close(ctx);
        }
    }

    public void close() {
        clearResources();
    }

    protected void finalize() throws Throwable {
        clearResources();
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.randomPadding_setRandom(this.cCtx, random);
    }

    public int getPaddingSizeLen() {
        return 4;
    }

    public int getPaddingLenMin() {
        return 5;
    }

    public AlgId algId() {
        return FoundationJNI.INSTANCE.randomPadding_algId(this.cCtx);
    }

    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.randomPadding_produceAlgInfo(this.cCtx);
    }

    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.randomPadding_restoreAlgInfo(this.cCtx, algInfo);
    }

    public void configure(PaddingParams params) {
        FoundationJNI.INSTANCE.randomPadding_configure(this.cCtx, params);
    }

    public int paddedDataLen(int dataLen) {
        return FoundationJNI.INSTANCE.randomPadding_paddedDataLen(this.cCtx, dataLen);
    }

    public int len() {
        return FoundationJNI.INSTANCE.randomPadding_len(this.cCtx);
    }

    public int lenMax() {
        return FoundationJNI.INSTANCE.randomPadding_lenMax(this.cCtx);
    }

    public void startDataProcessing() {
        FoundationJNI.INSTANCE.randomPadding_startDataProcessing(this.cCtx);
    }

    public byte[] processData(byte[] data) {
        return FoundationJNI.INSTANCE.randomPadding_processData(this.cCtx, data);
    }

    public byte[] finishDataProcessing() throws FoundationException {
        return FoundationJNI.INSTANCE.randomPadding_finishDataProcessing(this.cCtx);
    }

    public void startPaddedDataProcessing() {
        FoundationJNI.INSTANCE.randomPadding_startPaddedDataProcessing(this.cCtx);
    }

    public byte[] processPaddedData(byte[] data) {
        return FoundationJNI.INSTANCE.randomPadding_processPaddedData(this.cCtx, data);
    }

    public int finishPaddedDataProcessingOutLen() {
        return FoundationJNI.INSTANCE.randomPadding_finishPaddedDataProcessingOutLen(this.cCtx);
    }

    public byte[] finishPaddedDataProcessing() throws FoundationException {
        return FoundationJNI.INSTANCE.randomPadding_finishPaddedDataProcessing(this.cCtx);
    }

}
