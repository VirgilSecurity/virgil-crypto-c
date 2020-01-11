/// Copyright (C) 2015-2020 Virgil Security, Inc.
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

/// Provide conversion logic between OID and algorithm tags.
@objc(VSCFOid) public class Oid: NSObject {

    /// Return OID for given algorithm identifier.
    @objc public static func fromAlgId(algId: AlgId) -> Data {
        let proxyResult = vscf_oid_from_alg_id(vscf_alg_id_t(rawValue: UInt32(algId.rawValue)))

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return algorithm identifier for given OID.
    @objc public static func toAlgId(oid: Data) -> AlgId {
        let proxyResult = oid.withUnsafeBytes({ (oidPointer: UnsafeRawBufferPointer) -> vscf_alg_id_t in

            return vscf_oid_to_alg_id(vsc_data(oidPointer.bindMemory(to: byte.self).baseAddress, oid.count))
        })

        return AlgId.init(fromC: proxyResult)
    }

    /// Return OID for a given identifier.
    @objc public static func fromId(oidId: OidId) -> Data {
        let proxyResult = vscf_oid_from_id(vscf_oid_id_t(rawValue: UInt32(oidId.rawValue)))

        return Data.init(bytes: proxyResult.bytes, count: proxyResult.len)
    }

    /// Return identifier for a given OID.
    @objc public static func toId(oid: Data) -> OidId {
        let proxyResult = oid.withUnsafeBytes({ (oidPointer: UnsafeRawBufferPointer) -> vscf_oid_id_t in

            return vscf_oid_to_id(vsc_data(oidPointer.bindMemory(to: byte.self).baseAddress, oid.count))
        })

        return OidId.init(fromC: proxyResult)
    }

    /// Map oid identifier to the algorithm identifier.
    @objc public static func idToAlgId(oidId: OidId) -> AlgId {
        let proxyResult = vscf_oid_id_to_alg_id(vscf_oid_id_t(rawValue: UInt32(oidId.rawValue)))

        return AlgId.init(fromC: proxyResult)
    }

    /// Return true if given OIDs are equal.
    @objc public static func equal(lhs: Data, rhs: Data) -> Bool {
        let proxyResult = lhs.withUnsafeBytes({ (lhsPointer: UnsafeRawBufferPointer) -> Bool in
            rhs.withUnsafeBytes({ (rhsPointer: UnsafeRawBufferPointer) -> Bool in

                return vscf_oid_equal(vsc_data(lhsPointer.bindMemory(to: byte.self).baseAddress, lhs.count), vsc_data(rhsPointer.bindMemory(to: byte.self).baseAddress, rhs.count))
            })
        })

        return proxyResult
    }
}
