using System;
using System.Runtime.InteropServices;
using Virgil.Crypto.Foundation;

namespace Virgil.Crypto.Foundation
{
    public class SafeContextHandler : SafeHandle
    {

        public override bool IsInvalid { get { return handle == IntPtr.Zero; } }

        public SafeContextHandler(IntPtr handle) : base(handle, true)
        {
        }

        protected override bool ReleaseHandle()
        {                    
            C.vsf_impl_delete(this.handle);
            this.handle= IntPtr.Zero;
            return true;
        }
    }
}
