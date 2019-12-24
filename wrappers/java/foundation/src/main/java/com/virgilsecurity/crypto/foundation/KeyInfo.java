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

public class KeyInfo implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public KeyInfo() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyInfo_new();
    }

    /* Wrap underlying C context. */
    KeyInfo(FoundationContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Build key information based on the generic algorithm information.
    */
    public KeyInfo(AlgInfo algInfo) {
        super();
        this.cCtx = FoundationJNI.INSTANCE.keyInfo_new(algInfo);
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static KeyInfo getInstance(long cCtx) {
        FoundationContextHolder ctxHolder = new FoundationContextHolder(cCtx);
        return new KeyInfo(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.keyInfo_close(this.cCtx);
    }

    /*
    * Return true if a key is a compound key
    */
    public boolean isCompound() {
        return FoundationJNI.INSTANCE.keyInfo_isCompound(this.cCtx);
    }

    /*
    * Return true if a key is a hybrid key
    */
    public boolean isHybrid() {
        return FoundationJNI.INSTANCE.keyInfo_isHybrid(this.cCtx);
    }

    /*
    * Return true if a key is a compound key and compounds cipher key
    * and signer key are hybrid keys.
    */
    public boolean isCompoundHybrid() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybrid(this.cCtx);
    }

    /*
    * Return true if a key is a compound key and compounds cipher key
    * is a hybrid key.
    */
    public boolean isCompoundHybridCipher() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybridCipher(this.cCtx);
    }

    /*
    * Return true if a key is a compound key and compounds signer key
    * is a hybrid key.
    */
    public boolean isCompoundHybridSigner() {
        return FoundationJNI.INSTANCE.keyInfo_isCompoundHybridSigner(this.cCtx);
    }

    /*
    * Return true if a key is a compound key that contains hybrid keys
    * for encryption/decryption and signing/verifying that itself
    * contains a combination of classic keys and post-quantum keys.
    */
    public boolean isHybridPostQuantum() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantum(this.cCtx);
    }

    /*
    * Return true if a key is a compound key that contains a hybrid key
    * for encryption/decryption that contains a classic key and
    * a post-quantum key.
    */
    public boolean isHybridPostQuantumCipher() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantumCipher(this.cCtx);
    }

    /*
    * Return true if a key is a compound key that contains a hybrid key
    * for signing/verifying that contains a classic key and
    * a post-quantum key.
    */
    public boolean isHybridPostQuantumSigner() {
        return FoundationJNI.INSTANCE.keyInfo_isHybridPostQuantumSigner(this.cCtx);
    }

    /*
    * Return common type of the key.
    */
    public AlgId algId() {
        return FoundationJNI.INSTANCE.keyInfo_algId(this.cCtx);
    }

    /*
    * Return compound's cipher key id, if key is compound.
    * Return None, otherwise.
    */
    public AlgId compoundCipherAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundCipherAlgId(this.cCtx);
    }

    /*
    * Return compound's signer key id, if key is compound.
    * Return None, otherwise.
    */
    public AlgId compoundSignerAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundSignerAlgId(this.cCtx);
    }

    /*
    * Return hybrid's first key id, if key is hybrid.
    * Return None, otherwise.
    */
    public AlgId hybridFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_hybridFirstKeyAlgId(this.cCtx);
    }

    /*
    * Return hybrid's second key id, if key is hybrid.
    * Return None, otherwise.
    */
    public AlgId hybridSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_hybridSecondKeyAlgId(this.cCtx);
    }

    /*
    * Return hybrid's first key id of compound's cipher key,
    * if key is compound(hybrid, ...), None - otherwise.
    */
    public AlgId compoundHybridCipherFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridCipherFirstKeyAlgId(this.cCtx);
    }

    /*
    * Return hybrid's second key id of compound's cipher key,
    * if key is compound(hybrid, ...), None - otherwise.
    */
    public AlgId compoundHybridCipherSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridCipherSecondKeyAlgId(this.cCtx);
    }

    /*
    * Return hybrid's first key id of compound's signer key,
    * if key is compound(..., hybrid), None - otherwise.
    */
    public AlgId compoundHybridSignerFirstKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridSignerFirstKeyAlgId(this.cCtx);
    }

    /*
    * Return hybrid's second key id of compound's signer key,
    * if key is compound(..., hybrid), None - otherwise.
    */
    public AlgId compoundHybridSignerSecondKeyAlgId() {
        return FoundationJNI.INSTANCE.keyInfo_compoundHybridSignerSecondKeyAlgId(this.cCtx);
    }
}

