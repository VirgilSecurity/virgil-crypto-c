<?php
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
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

interface Asn1Reader extends Ctx
{

    /**
    *
    * @param string $$data
    * @return void
    */
    public function reset(string $$data): void
    {
        ($this->ctx, $$data);
    }

    /**
    *
    * @return int
    */
    public function leftLen(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function hasError(): bool
    {
        return ($this->ctx);
    }

    /**
    *
    * @return void
    * @throws \Exception
    */
    public function status(): void
    {
        ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function getTag(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function getLen(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function getDataLen(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @param int $$tag
    * @return int
    */
    public function readTag(int $$tag): int
    {
        return ($this->ctx, $$tag);
    }

    /**
    *
    * @param int $$tag
    * @return int
    */
    public function readContextTag(int $$tag): int
    {
        return ($this->ctx, $$tag);
    }

    /**
    *
    * @return int
    */
    public function readInt(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readInt8(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readInt16(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readInt32(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readInt64(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readUint(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readUint8(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readUint16(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readUint32(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readUint64(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return bool
    */
    public function readBool(): bool
    {
        return ($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function readNull(): void
    {
        ($this->ctx);
    }

    /**
    *
    * @return void
    */
    public function readNullOptional(): void
    {
        ($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function readOctetStr(): string
    {
        return ($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function readBitstringAsOctetStr(): string
    {
        return ($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function readUtf8Str(): string
    {
        return ($this->ctx);
    }

    /**
    *
    * @return string
    */
    public function readOid(): string
    {
        return ($this->ctx);
    }

    /**
    *
    * @param int $$len
    * @return string
    */
    public function readData(int $$len): string
    {
        return ($this->ctx, $$len);
    }

    /**
    *
    * @return int
    */
    public function readSequence(): int
    {
        return ($this->ctx);
    }

    /**
    *
    * @return int
    */
    public function readSet(): int
    {
        return ($this->ctx);
    }

}
