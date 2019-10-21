package foundation

import "C"

/*
* Contains private part of the key.
*/
type IPrivateKey interface {

    IKey

    /*
    * Extract public key from the private key.
    */
    ExtractPublicKey () IPublicKey
}

