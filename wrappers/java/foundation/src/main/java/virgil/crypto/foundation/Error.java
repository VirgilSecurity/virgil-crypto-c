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

package virgil.crypto.foundation;

/*
* Error context.
* Can be used for sequential operations, i.e. parsers, to accumulate error.
* In this way operation is successful if all steps are successful, otherwise
* last occurred error code can be obtained.
*/
public class Error implements AutoCloseable {

    public long cCtx;

    /* Create underlying C context. */
    public Error() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.error_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public Error(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /* Close resource. */
    public void close() {
        FoundationJNI.INSTANCE.error_close(this.cCtx);
    }

    /*
    * Reset context to the "no error" state.
    */
    public void reset() {
        FoundationJNI.INSTANCE.error_reset(this.cCtx);
    }

    /*
    * Return true if status is not "success".
    */
    public boolean hasError() {
        return FoundationJNI.INSTANCE.error_hasError(this.cCtx);
    }

    /*
    * Return error code.
    */
    public void status() throws FoundationException {
        FoundationJNI.INSTANCE.error_status(this.cCtx);
    }
}

