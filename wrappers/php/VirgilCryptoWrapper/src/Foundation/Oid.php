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

/**
* Provide conversion logic between OID and algorithm tags.
*/
class Oid
{

    /**
    * Return OID for given algorithm identifier.
    *
    * @param AlgId $algId
    * @return string
    */
    public static function fromAlgId(AlgId $algId): string
    {
        return vscf_oid_from_alg_id_php($algId->getValue());
    }

    /**
    * Return algorithm identifier for given OID.
    *
    * @param string $oid
    * @return AlgId
    */
    public static function toAlgId(string $oid): AlgId
    {
        $enum = vscf_oid_to_alg_id_php($oid);
        return new AlgId($enum);
    }

    /**
    * Return OID for a given identifier.
    *
    * @param OidId $oidId
    * @return string
    */
    public static function fromId(OidId $oidId): string
    {
        return vscf_oid_from_id_php($oidId->getValue());
    }

    /**
    * Return identifier for a given OID.
    *
    * @param string $oid
    * @return OidId
    */
    public static function toId(string $oid): OidId
    {
        $enum = vscf_oid_to_id_php($oid);
        return new OidId($enum);
    }

    /**
    * Map oid identifier to the algorithm identifier.
    *
    * @param OidId $oidId
    * @return AlgId
    */
    public static function idToAlgId(OidId $oidId): AlgId
    {
        $enum = vscf_oid_id_to_alg_id_php($oidId->getValue());
        return new AlgId($enum);
    }

    /**
    * Return true if given OIDs are equal.
    *
    * @param string $lhs
    * @param string $rhs
    * @return bool
    */
    public static function equal(string $lhs, string $rhs): bool
    {
        return vscf_oid_equal_php($lhs, $rhs);
    }
}
