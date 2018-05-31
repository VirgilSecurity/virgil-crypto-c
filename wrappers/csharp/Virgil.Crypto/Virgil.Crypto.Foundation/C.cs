using System;
using System.Runtime.InteropServices;

namespace Virgil.Crypto.Foundation
{
    internal class C
    {
        [DllImport("vsf")]
        internal static extern void vsf_impl_delete(IntPtr impl);

        [DllImport("vsf")]
        internal static extern IntPtr vsf_sha256_new();

        [DllImport("vsf")]
        internal static extern void vsf_sha256_hash(IntPtr data, int data_len, IntPtr digest, int digest_len);

    }

    internal class Constants {
        internal static uint Sha256_DIGEST_SIZE = 32;
    }
}
