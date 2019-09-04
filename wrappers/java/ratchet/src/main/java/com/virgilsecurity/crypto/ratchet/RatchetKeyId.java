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

package com.virgilsecurity.crypto.ratchet;

import com.virgilsecurity.crypto.foundation.*;

/*
* Utils class for working with keys formats.
*/
public class RatchetKeyId implements AutoCloseable {

    public java.nio.ByteBuffer cCtx;

    /* Create underlying C context. */
    public RatchetKeyId() {
        super();
        this.cCtx = RatchetJNI.INSTANCE.ratchetKeyId_new();
    }

    /* Wrap underlying C context. */
    RatchetKeyId(RatchetContextHolder contextHolder) {
        this.cCtx = contextHolder.cCtx;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static RatchetKeyId getInstance(java.nio.ByteBuffer cCtx) {
        RatchetContextHolder ctxHolder = new RatchetContextHolder(cCtx);
        return new RatchetKeyId(ctxHolder);
    }

    /* Close resource. */
    public void close() {
        RatchetJNI.INSTANCE.ratchetKeyId_close(this.cCtx);
    }

    /*
    * Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key
    */
    public byte[] computePublicKeyId(byte[] publicKey) throws RatchetException {
        return RatchetJNI.INSTANCE.ratchetKeyId_computePublicKeyId(this.cCtx, publicKey);
    }
}

