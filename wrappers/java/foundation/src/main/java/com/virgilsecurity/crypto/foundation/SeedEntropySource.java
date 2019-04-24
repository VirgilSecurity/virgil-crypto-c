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
* Deterministic entropy source that is based only on the given seed.
*/
public class SeedEntropySource implements AutoCloseable, EntropySource {

    public long cCtx;

    /* Create underlying C context. */
    public SeedEntropySource() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.seedEntropySource_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public SeedEntropySource(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * The maximum length of the entropy requested at once.
    */
    public int getGatherLenMax() {
        return 48;
    }

    /*
    * Set a new seed as an entropy source.
    */
    public void resetSeed(byte[] seed) {
        FoundationJNI.INSTANCE.seedEntropySource_resetSeed(this.cCtx, seed);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.seedEntropySource_close(this.cCtx);
    }

    /*
    * Defines that implemented source is strong.
    */
    public boolean isStrong() {
        return FoundationJNI.INSTANCE.seedEntropySource_isStrong(this.cCtx);
    }

    /*
    * Gather entropy of the requested length.
    */
    public byte[] gather(int len) throws FoundationException {
        return FoundationJNI.INSTANCE.seedEntropySource_gather(this.cCtx, len);
    }
}

