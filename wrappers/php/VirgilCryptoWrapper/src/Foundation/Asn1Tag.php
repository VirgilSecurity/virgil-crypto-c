<?php
/**
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

namespace Virgil\CryptoWrapper\Foundation;

use MyCLabs\Enum\Enum;

/**
* ASN.1 constants.
*/
class Asn1Tag extends Enum
{

    private const BOOLEAN = "0x01";
    private const INTEGER = "0x02";
    private const BIT_STRING = "0x03";
    private const OCTET_STRING = "0x04";
    private const NULL = "0x05";
    private const OID = "0x06";
    private const UTF8_STRING = "0x0C";
    private const SEQUENCE = "0x10";
    private const SET = "0x11";
    private const PRINTABLE_STRING = "0x13";
    private const T61_STRING = "0x14";
    private const IA5_STRING = "0x16";
    private const UTC_TIME = "0x17";
    private const GENERALIZED_TIME = "0x18";
    private const UNIVERSAL_STRING = "0x1C";
    private const BMP_STRING = "0x1E";
    private const PRIMITIVE = "0x00";
    private const CONSTRUCTED = "0x20";
    private const CONTEXT_SPECIFIC = "0x80";
}
