/// Copyright (C) 2015-2018 Virgil Security Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCFoundation
import VirgilCryptoCommon

/// Provide conversion logic between OID and algorithm tags.
@objc(VSCFOid) public class Oid: NSObject {

    /// Return OID for given key algorithm.
    @objc public static func fromKeyAlg(keyAlg: KeyAlg) -> Data {
        let proxyResult = vscf_oid_from_key_alg(vscf_key_alg_t(rawValue: UInt32(keyAlg.rawValue)))

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return key algorithm for given OID.
    @objc public static func toKeyAlg(oid: Data) -> KeyAlg {
        let proxyResult = oid.withUnsafeBytes({ (oidPointer: UnsafePointer<byte>) -> vscf_key_alg_t in
            return vscf_oid_to_key_alg(vsc_data(oidPointer, oid.count))
        })

        return KeyAlg.init(fromC: proxyResult)
    }

    /// Return OID for given algorithm.
    @objc public static func fromAlg(alg: Alg) -> Data {
        let proxyResult = vscf_oid_from_alg(vscf_alg_t(rawValue: UInt32(alg.rawValue)))

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return algorithm for given OID.
    @objc public static func toAlg(oid: Data) -> Alg {
        let proxyResult = oid.withUnsafeBytes({ (oidPointer: UnsafePointer<byte>) -> vscf_alg_t in
            return vscf_oid_to_alg(vsc_data(oidPointer, oid.count))
        })

        return Alg.init(fromC: proxyResult)
    }

    /// Return true if given OIDs are equal.
    @objc public static func equal(lhs: Data, rhs: Data) -> Bool {
        let proxyResult = lhs.withUnsafeBytes({ (lhsPointer: UnsafePointer<byte>) -> Bool in
            rhs.withUnsafeBytes({ (rhsPointer: UnsafePointer<byte>) -> Bool in
                return vscf_oid_equal(vsc_data(lhsPointer, lhs.count), vsc_data(rhsPointer, rhs.count))
            })
        })

        return proxyResult
    }
}
