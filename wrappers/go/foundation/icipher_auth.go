package foundation

import "C"

/*
* Mix-in interface that provides specific functionality to authenticated
* encryption and decryption (AEAD ciphers).
*/
type ICipherAuth interface {

    context

    /*
    * Set additional data for for AEAD ciphers.
    */
    SetAuthData (authData []byte)

    /*
    * Accomplish an authenticated encryption and place tag separately.
    *
    * Note, if authentication tag should be added to an encrypted data,
    * method "finish" can be used.
    */
    FinishAuthEncryption () ([]byte, []byte, error)

    /*
    * Accomplish an authenticated decryption with explicitly given tag.
    *
    * Note, if authentication tag is a part of an encrypted data then,
    * method "finish" can be used for simplicity.
    */
    FinishAuthDecryption (tag []byte) ([]byte, error)
}

