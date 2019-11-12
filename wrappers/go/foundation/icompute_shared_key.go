package foundation

import "C"

/*
* Provide interface to compute shared key for 2 asymmetric keys.
*/
type IComputeSharedKey interface {

    context

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) ([]byte, error)

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    SharedKeyLen (key IKey) uint32

    /*
    * Release underlying C context.
    */
    Delete ()
}

