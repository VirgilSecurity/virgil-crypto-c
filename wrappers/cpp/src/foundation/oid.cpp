// Copyright (C) 2015-2026 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <virgil/crypto/foundation/oid.hpp>
#include <virgil/crypto/foundation/vscf_oid.h>
#include <virgil/crypto/foundation/vscf_impl.h>
#include <virgil/crypto/foundation/alg_id.hpp>
#include <virgil/crypto/foundation/oid_id.hpp>

namespace virgil::crypto::foundation {

std::vector<uint8_t> Oid::from_alg_id(AlgId alg_id) {
    auto proxy_result = vscf_oid_from_alg_id(static_cast<vscf_alg_id_t>(alg_id));
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

AlgId Oid::to_alg_id(std::span<const uint8_t> oid) {
    auto proxy_result = vscf_oid_to_alg_id(vsc_data(oid.data(), oid.size()));
    return static_cast<AlgId>(proxy_result);
}

std::vector<uint8_t> Oid::from_id(OidId oid_id) {
    auto proxy_result = vscf_oid_from_id(static_cast<vscf_oid_id_t>(oid_id));
    return std::vector<uint8_t>(proxy_result.bytes, proxy_result.bytes + proxy_result.len);
}

OidId Oid::to_id(std::span<const uint8_t> oid) {
    auto proxy_result = vscf_oid_to_id(vsc_data(oid.data(), oid.size()));
    return static_cast<OidId>(proxy_result);
}

AlgId Oid::id_to_alg_id(OidId oid_id) {
    auto proxy_result = vscf_oid_id_to_alg_id(static_cast<vscf_oid_id_t>(oid_id));
    return static_cast<AlgId>(proxy_result);
}

bool Oid::equal(std::span<const uint8_t> lhs, std::span<const uint8_t> rhs) {
    auto proxy_result = vscf_oid_equal(vsc_data(lhs.data(), lhs.size()), vsc_data(rhs.data(), rhs.size()));
    return proxy_result;
}

}  // namespace virgil::crypto::foundation
