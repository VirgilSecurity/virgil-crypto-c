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

public class MessageInfoCustomParams implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public MessageInfoCustomParams() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.messageInfoCustomParams_new();
    }

    public int getOfIntType() {
        return 1;
    }

    public int getOfStringType() {
        return 2;
    }

    public int getOfDataType() {
        return 3;
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public static MessageInfoCustomParams getInstance(long cCtx) {
        MessageInfoCustomParams newInstance = new MessageInfoCustomParams();
        newInstance.cCtx = cCtx;
        return newInstance;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.messageInfoCustomParams_close(this.cCtx);
    }

    /*
    * Add custom parameter with integer value.
    */
    public void addInt(byte[] key, int value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addInt(this.cCtx, key, value);
    }

    /*
    * Add custom parameter with UTF8 string value.
    */
    public void addString(byte[] key, byte[] value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addString(this.cCtx, key, value);
    }

    /*
    * Add custom parameter with octet string value.
    */
    public void addData(byte[] key, byte[] value) {
        FoundationJNI.INSTANCE.messageInfoCustomParams_addData(this.cCtx, key, value);
    }

    /*
    * Remove all parameters.
    */
    public void clear() {
        FoundationJNI.INSTANCE.messageInfoCustomParams_clear(this.cCtx);
    }

    /*
    * Return custom parameter with integer value.
    */
    public int findInt(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findInt(this.cCtx, key);
    }

    /*
    * Return custom parameter with UTF8 string value.
    */
    public byte[] findString(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findString(this.cCtx, key);
    }

    /*
    * Return custom parameter with octet string value.
    */
    public byte[] findData(byte[] key) throws FoundationException {
        return FoundationJNI.INSTANCE.messageInfoCustomParams_findData(this.cCtx, key);
    }
}

