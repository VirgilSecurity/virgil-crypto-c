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
* Handles chained public key.
*
* Chained public key contains 2 public keys:
* - l1 key:
* - can be used for plain text encryption;
* - can be used to verify l1 signature;
* - l2 key:
* - can be used for l1 output encryption;
* - can be used to verify l2 signature.
*/
public class ChainedPublicKey implements AutoCloseable, Key, PublicKey {

    public long cCtx;

    /* Create underlying C context. */
    public ChainedPublicKey() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.chainedPublicKey_new();
    }

    /* Wrap underlying C context. */
    ChainedPublicKey(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Return l1 public key.
    */
    public PublicKey l1Key() {
        return FoundationJNI.INSTANCE.chainedPublicKey_l1Key(this.cCtx);
    }

    /*
    * Return l2 public key.
    */
    public PublicKey l2Key() {
        return FoundationJNI.INSTANCE.chainedPublicKey_l2Key(this.cCtx);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static ChainedPublicKey getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new ChainedPublicKey(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.chainedPublicKey_close(this.cCtx);
    }

    /*
    * Algorithm identifier the key belongs to.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.chainedPublicKey_algId(this.cCtx);
    }

    /*
    * Return algorithm information that can be used for serialization.
    */
    public AlgInfo algInfo() {
        return FoundationJNI.INSTANCE.chainedPublicKey_algInfo(this.cCtx);
    }

    /*
    * Length of the key in bytes.
    */
    public int len() {
        return FoundationJNI.INSTANCE.chainedPublicKey_len(this.cCtx);
    }

    /*
    * Length of the key in bits.
    */
    public int bitlen() {
        return FoundationJNI.INSTANCE.chainedPublicKey_bitlen(this.cCtx);
    }

    /*
    * Check that key is valid.
    * Note, this operation can be slow.
    */
    public boolean isValid() {
        return FoundationJNI.INSTANCE.chainedPublicKey_isValid(this.cCtx);
    }
}

