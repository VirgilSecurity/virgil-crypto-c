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

package com.virgilsecurity.crypto.foundation;

/*
* Random number generator that is used for test purposes only.
*/
public class FakeRandom implements AutoCloseable, Random, EntropySource {

    public long cCtx;

    /* Create underlying C context. */
    public FakeRandom() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.fakeRandom_new();
    }

    /* Wrap underlying C context. */
    FakeRandom(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Configure random number generator to generate sequence filled with given byte.
    */
    public void setupSourceByte(byte byteSource) {
        FoundationJNI.INSTANCE.fakeRandom_setupSourceByte(this.cCtx, byteSource);
    }

    /*
    * Configure random number generator to generate random sequence from given data.
    * Note, that given data is used as circular source.
    */
    public void setupSourceData(byte[] dataSource) {
        FoundationJNI.INSTANCE.fakeRandom_setupSourceData(this.cCtx, dataSource);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static FakeRandom getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new FakeRandom(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.fakeRandom_close(this.cCtx);
    }

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    public byte[] random(int dataLen) throws FoundationException {
        return FoundationJNI.INSTANCE.fakeRandom_random(this.cCtx, dataLen);
    }

    /*
    * Retrieve new seed data from the entropy sources.
    */
    public void reseed() throws FoundationException {
        FoundationJNI.INSTANCE.fakeRandom_reseed(this.cCtx);
    }

    /*
    * Defines that implemented source is strong.
    */
    public boolean isStrong() {
        return FoundationJNI.INSTANCE.fakeRandom_isStrong(this.cCtx);
    }

    /*
    * Gather entropy of the requested length.
    */
    public byte[] gather(int len) throws FoundationException {
        return FoundationJNI.INSTANCE.fakeRandom_gather(this.cCtx, len);
    }
}

