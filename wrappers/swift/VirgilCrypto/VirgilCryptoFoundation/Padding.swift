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
import VSCFoundation

/// Provide an interface to add and remove data padding.
@objc(VSCFPadding) public protocol Padding : CContext {

    /// Set new padding parameters.
    @objc func configure(params: PaddingParams)

    /// Return length in bytes of a data with a padding.
    @objc func paddedDataLen(dataLen: Int) -> Int

    /// Return an actual number of padding in bytes.
    /// Note, this method might be called right before "finish data processing".
    @objc func len() -> Int

    /// Return a maximum number of padding in bytes.
    @objc func lenMax() -> Int

    /// Prepare the algorithm to process data.
    @objc func startDataProcessing()

    /// Only data length is needed to produce padding later.
    /// Return data that should be further proceeded.
    @objc func processData(data: Data) -> Data

    /// Accomplish data processing and return padding.
    @objc func finishDataProcessing() throws -> Data

    /// Prepare the algorithm to process padded data.
    @objc func startPaddedDataProcessing()

    /// Process padded data.
    /// Return filtered data without padding.
    @objc func processPaddedData(data: Data) -> Data

    /// Accomplish padded data processing and return left data without a padding.
    @objc func finishPaddedDataProcessing() throws -> Data
}
