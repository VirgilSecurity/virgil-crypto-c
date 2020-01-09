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

package com.virgilsecurity.crypto.foundation;

/*
* Append a random number of padding bytes to a data.
*/
public class RandomPadding implements AutoCloseable, Alg, Padding {

    public long cCtx;

    /* Create underlying C context. */
    public RandomPadding() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.randomPadding_new();
    }

    /* Wrap underlying C context. */
    RandomPadding(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    public void setRandom(Random random) {
        FoundationJNI.INSTANCE.randomPadding_setRandom(this.cCtx, random);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RandomPadding getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new RandomPadding(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.randomPadding_close(this.cCtx);
    }

    /*
    * Provide algorithm identificator.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.randomPadding_algId(this.cCtx);
    }

    /*
    * Produce object with algorithm information and configuration parameters.
    */
    public AlgInfo produceAlgInfo() {
        return FoundationJNI.INSTANCE.randomPadding_produceAlgInfo(this.cCtx);
    }

    /*
    * Restore algorithm configuration from the given object.
    */
    public void restoreAlgInfo(AlgInfo algInfo) throws FoundationException {
        FoundationJNI.INSTANCE.randomPadding_restoreAlgInfo(this.cCtx, algInfo);
    }

    /*
    * Set new padding parameters.
    */
    public void configure(PaddingParams params) {
        FoundationJNI.INSTANCE.randomPadding_configure(this.cCtx, params);
    }

    /*
    * Return length in bytes of a data with a padding.
    */
    public int paddedDataLen(int dataLen) {
        return FoundationJNI.INSTANCE.randomPadding_paddedDataLen(this.cCtx, dataLen);
    }

    /*
    * Return an actual number of padding in bytes.
    * Note, this method might be called right before "finish data processing".
    */
    public int len() {
        return FoundationJNI.INSTANCE.randomPadding_len(this.cCtx);
    }

    /*
    * Return a maximum number of padding in bytes.
    */
    public int lenMax() {
        return FoundationJNI.INSTANCE.randomPadding_lenMax(this.cCtx);
    }

    /*
    * Prepare the algorithm to process data.
    */
    public void startDataProcessing() {
        FoundationJNI.INSTANCE.randomPadding_startDataProcessing(this.cCtx);
    }

    /*
    * Only data length is needed to produce padding later.
    * Return data that should be further proceeded.
    */
    public byte[] processData(byte[] data) {
        return FoundationJNI.INSTANCE.randomPadding_processData(this.cCtx, data);
    }

    /*
    * Accomplish data processing and return padding.
    */
    public byte[] finishDataProcessing() throws FoundationException {
        return FoundationJNI.INSTANCE.randomPadding_finishDataProcessing(this.cCtx);
    }

    /*
    * Prepare the algorithm to process padded data.
    */
    public void startPaddedDataProcessing() {
        FoundationJNI.INSTANCE.randomPadding_startPaddedDataProcessing(this.cCtx);
    }

    /*
    * Process padded data.
    * Return filtered data without padding.
    */
    public byte[] processPaddedData(byte[] data) {
        return FoundationJNI.INSTANCE.randomPadding_processPaddedData(this.cCtx, data);
    }

    /*
    * Return length in bytes required hold output of the method
    * "finish padded data processing".
    */
    public int finishPaddedDataProcessingOutLen() {
        return FoundationJNI.INSTANCE.randomPadding_finishPaddedDataProcessingOutLen(this.cCtx);
    }

    /*
    * Accomplish padded data processing and return left data without a padding.
    */
    public byte[] finishPaddedDataProcessing() throws FoundationException {
        return FoundationJNI.INSTANCE.randomPadding_finishPaddedDataProcessing(this.cCtx);
    }
}

