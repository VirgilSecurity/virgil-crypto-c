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
* Simple PEM wrapper.
*/
public class Pem {

    /*
    * Return length in bytes required to hold wrapped PEM format.
    */
    public static int wrappedLen(String title, int dataLen) {
        return FoundationJNI.INSTANCE.pem_wrappedLen(title, dataLen);
    }

    /*
    * Takes binary data and wraps it to the simple PEM format - no
    * additional information just header-base64-footer.
    * Note, written buffer is NOT null-terminated.
    */
    public static byte[] wrap(String title, byte[] data) {
        return FoundationJNI.INSTANCE.pem_wrap(title, data);
    }

    /*
    * Return length in bytes required to hold unwrapped binary.
    */
    public static int unwrappedLen(int pemLen) {
        return FoundationJNI.INSTANCE.pem_unwrappedLen(pemLen);
    }

    /*
    * Takes PEM data and extract binary data from it.
    */
    public static byte[] unwrap(byte[] pem) throws FoundationException {
        return FoundationJNI.INSTANCE.pem_unwrap(pem);
    }

    /*
    * Returns PEM title if PEM data is valid, otherwise - empty data.
    */
    public static byte[] title(byte[] pem) {
        return FoundationJNI.INSTANCE.pem_title(pem);
    }
}

