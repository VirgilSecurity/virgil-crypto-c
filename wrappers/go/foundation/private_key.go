package foundation

import "C"

/*
* Contains private part of the key.
*/
type PrivateKey interface {

    context

    /*
    * Extract public key from the private key.
    */
    ExtractPublicKey () (PublicKey, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

