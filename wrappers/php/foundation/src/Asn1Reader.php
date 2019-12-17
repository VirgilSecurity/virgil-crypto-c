<?php
/**
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

namespace Virgil\CryptoWrapper\Foundation;

/**
* Provides interface to the ASN.1 reader.
* Note, that all "read" methods move reading position forward.
* Note, that all "get" do not change reading position.
*/
interface Asn1Reader extends Ctx
{

    /**
    * Reset all internal states and prepare to new ASN.1 reading operations.
    *
    * @param string $data
    * @return void
    */
    public function reset(string $data): void;

    /**
    * Return length in bytes how many bytes are left for reading.
    *
    * @return int
    */
    public function leftLen(): int;

    /**
    * Return true if status is not "success".
    *
    * @return bool
    */
    public function hasError(): bool;

    /**
    * Return error code.
    *
    * @return void
    * @throws \Exception
    */
    public function status(): void;

    /**
    * Get tag of the current ASN.1 element.
    *
    * @return int
    */
    public function getTag(): int;

    /**
    * Get length of the current ASN.1 element.
    *
    * @return int
    */
    public function getLen(): int;

    /**
    * Get length of the current ASN.1 element with tag and length itself.
    *
    * @return int
    */
    public function getDataLen(): int;

    /**
    * Read ASN.1 type: TAG.
    * Return element length.
    *
    * @param int $tag
    * @return int
    */
    public function readTag(int $tag): int;

    /**
    * Read ASN.1 type: context-specific TAG.
    * Return element length.
    * Return 0 if current position do not points to the requested tag.
    *
    * @param int $tag
    * @return int
    */
    public function readContextTag(int $tag): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt8(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt16(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt32(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readInt64(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint8(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint16(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint32(): int;

    /**
    * Read ASN.1 type: INTEGER.
    *
    * @return int
    */
    public function readUint64(): int;

    /**
    * Read ASN.1 type: BOOLEAN.
    *
    * @return bool
    */
    public function readBool(): bool;

    /**
    * Read ASN.1 type: NULL.
    *
    * @return void
    */
    public function readNull(): void;

    /**
    * Read ASN.1 type: NULL, only if it exists.
    * Note, this method is safe to call even no more data is left for reading.
    *
    * @return void
    */
    public function readNullOptional(): void;

    /**
    * Read ASN.1 type: OCTET STRING.
    *
    * @return string
    */
    public function readOctetStr(): string;

    /**
    * Read ASN.1 type: BIT STRING.
    *
    * @return string
    */
    public function readBitstringAsOctetStr(): string;

    /**
    * Read ASN.1 type: UTF8String.
    *
    * @return string
    */
    public function readUtf8Str(): string;

    /**
    * Read ASN.1 type: OID.
    *
    * @return string
    */
    public function readOid(): string;

    /**
    * Read raw data of given length.
    *
    * @param int $len
    * @return string
    */
    public function readData(int $len): string;

    /**
    * Read ASN.1 type: SEQUENCE.
    * Return element length.
    *
    * @return int
    */
    public function readSequence(): int;

    /**
    * Read ASN.1 type: SET.
    * Return element length.
    *
    * @return int
    */
    public function readSet(): int;
}
