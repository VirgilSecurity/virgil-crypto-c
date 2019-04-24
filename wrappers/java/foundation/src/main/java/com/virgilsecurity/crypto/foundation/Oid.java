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
* Provide conversion logic between OID and algorithm tags.
*/
public class Oid {

    /*
    * Return OID for given algorithm identifier.
    */
    public static byte[] fromAlgId(AlgId algId) {
        return FoundationJNI.INSTANCE.oid_fromAlgId(algId);
    }

    /*
    * Return algorithm identifier for given OID.
    */
    public static AlgId toAlgId(byte[] oid) {
        return FoundationJNI.INSTANCE.oid_toAlgId(oid);
    }

    /*
    * Return OID for a given identifier.
    */
    public static byte[] fromId(OidId oidId) {
        return FoundationJNI.INSTANCE.oid_fromId(oidId);
    }

    /*
    * Return identifier for a given OID.
    */
    public static OidId toId(byte[] oid) {
        return FoundationJNI.INSTANCE.oid_toId(oid);
    }

    /*
    * Return true if given OIDs are equal.
    */
    public static boolean equal(byte[] lhs, byte[] rhs) {
        return FoundationJNI.INSTANCE.oid_equal(lhs, rhs);
    }
}

