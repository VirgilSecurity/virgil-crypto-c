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

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <tl/expected.hpp>
#include <memory>
#include <virgil/crypto/foundation/error.hpp>
#include <virgil/crypto/foundation/random.hpp>

struct vscf_ctr_drbg_t;
struct vscf_impl_t;

namespace virgil::crypto::foundation {

class EntropySource;

/// Implementation of the RNG using deterministic random bit generators
/// based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
/// This class is thread-safe if the build option .(c_global_macros_multi_threading) was enabled.
class CtrDrbg : virtual public Random {
public:
    CtrDrbg();
    /// Adopt ownership of an existing C handle.
    explicit CtrDrbg(vscf_ctr_drbg_t* c_ctx) noexcept;
    CtrDrbg(const CtrDrbg& other);
    CtrDrbg(CtrDrbg&& other) noexcept;
    CtrDrbg& operator=(const CtrDrbg& other);
    CtrDrbg& operator=(CtrDrbg&& other) noexcept;
    ~CtrDrbg();

    /// The underlying concrete C handle (non-owning).
    vscf_ctr_drbg_t* c_ctx() const noexcept;

    /// The polymorphic C implementation handle (non-owning).
    vscf_impl_t* impl() const noexcept override;

    /// The interval before reseed is performed by default.
    static constexpr std::size_t RESEED_INTERVAL = 10000;

    /// The amount of entropy used per seed by default.
    static constexpr std::size_t ENTROPY_LEN = 48;

    tl::expected<void, Error> set_entropy_source(const EntropySource& entropy_source);

    /// Setup predefined values to the uninitialized class dependencies.
    tl::expected<void, Error> setup_defaults();

    /// Force entropy to be gathered at the beginning of every call to
    /// the .(class_ctr_drbg_method_random)() method.
    /// Note, use this if your entropy source has sufficient throughput.
    void enable_prediction_resistance();

    /// Sets the reseed interval.
    /// Default value is .(class_ctr_drbg_constant_reseed_interval).
    void set_reseed_interval(std::size_t interval);

    /// Sets the amount of entropy grabbed on each seed or reseed.
    /// The default value is .(class_ctr_drbg_constant_entropy_len).
    void set_entropy_len(std::size_t len);

    /// Generate random bytes.
    /// All RNG implementations must be thread-safe.
    tl::expected<std::vector<uint8_t>, Error> random(std::size_t data_len) const override;

    /// Retrieve new seed data from the entropy sources.
    tl::expected<void, Error> reseed() override;

private:
    vscf_ctr_drbg_t* c_ctx_;
};

}  // namespace virgil::crypto::foundation
