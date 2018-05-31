//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;

namespace Virgil.Crypto.Foundation
{
    public class Sha256 : IHash, IDisposable
    {
        private HandleRef impl_;

        public Sha256()
        {
            impl_ = new HandleRef(this, C.vsf_sha256_new());
        }

        public byte[] hash(byte[] data)
        {
            var digest = new byte[Constants.Sha256_DIGEST_SIZE];

            GCHandle pinnedData = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr dataPtr = pinnedData.AddrOfPinnedObject();

            GCHandle pinnedDigest= GCHandle.Alloc(digest, GCHandleType.Pinned);
            IntPtr digestPtr = pinnedDigest.AddrOfPinnedObject();

            C.vsf_sha256_hash(dataPtr, data.Length, digestPtr, digest.Length);

            pinnedData.Free();
            pinnedDigest.Free();

            return digest;
        }

        public void Dispose()
        {
            C.vsf_impl_delete(impl_.Handle);
        }
    }
}
