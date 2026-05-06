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

public interface Asn1Writer {
    void reset(byte[] out, int outLen);

    int finish(boolean doNotAdjust);

    byte bytes();

    int len();

    int writtenLen();

    int unwrittenLen();

    boolean hasError();

    void status() throws FoundationException;

    byte reserve(int len);

    int writeTag(int tag);

    int writeContextTag(int tag, int len);

    int writeLen(int len);

    int writeInt(int value);

    int writeInt8(byte value);

    int writeInt16(short value);

    int writeInt32(int value);

    int writeInt64(long value);

    int writeUint(int value);

    int writeUint8(int value);

    int writeUint16(int value);

    int writeUint32(int value);

    int writeUint64(long value);

    int writeBool(boolean value);

    int writeNull();

    int writeOctetStr(byte[] value);

    int writeOctetStrAsBitstring(byte[] value);

    int writeData(byte[] data);

    int writeUtf8Str(byte[] value);

    int writeOid(byte[] value);

    int writeSequence(int len);

    int writeSet(int len);

}
