/// Copyright (C) 2015-2019 Virgil Security, Inc.
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
import VSCRatchet
import VirgilCryptoFoundation

/// Group ticket used to start group session.
@objc(VSCRRatchetGroupTicket) public class RatchetGroupTicket: NSObject {

    /// Handle underlying C context.
    @objc public let c_ctx: OpaquePointer

    /// Create underlying C context.
    public override init() {
        self.c_ctx = vscr_ratchet_group_ticket_new()
        super.init()
    }

    /// Acquire C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(take c_ctx: OpaquePointer) {
        self.c_ctx = c_ctx
        super.init()
    }

    /// Acquire retained C context.
    /// Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    public init(use c_ctx: OpaquePointer) {
        self.c_ctx = vscr_ratchet_group_ticket_shallow_copy(c_ctx)
        super.init()
    }

    /// Release underlying C context.
    deinit {
        vscr_ratchet_group_ticket_delete(self.c_ctx)
    }

    /// Random used to generate keys
    @objc public func setRng(rng: Random) {
        vscr_ratchet_group_ticket_release_rng(self.c_ctx)
        vscr_ratchet_group_ticket_use_rng(self.c_ctx, rng.c_ctx)
    }

    /// Setups default dependencies:
    /// - RNG: CTR DRBG
    @objc public func setupDefaults() throws {
        let proxyResult = vscr_ratchet_group_ticket_setup_defaults(self.c_ctx)

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Adds participant to chat.
    @objc public func addParticipant(participantId: Data, publicKey: Data) throws {
        let proxyResult = participantId.withUnsafeBytes({ (participantIdPointer: UnsafePointer<byte>) -> vscr_status_t in
            publicKey.withUnsafeBytes({ (publicKeyPointer: UnsafePointer<byte>) -> vscr_status_t in

                return vscr_ratchet_group_ticket_add_participant(self.c_ctx, vsc_data(participantIdPointer, participantId.count), vsc_data(publicKeyPointer, publicKey.count))
            })
        })

        try RatchetError.handleStatus(fromC: proxyResult)
    }

    /// Generates message that should be sent to all participants using secure channel.
    @objc public func generateTicket() -> RatchetGroupMessage {
        let proxyResult = vscr_ratchet_group_ticket_generate_ticket(self.c_ctx)

        return RatchetGroupMessage.init(use: proxyResult!)
    }
}
