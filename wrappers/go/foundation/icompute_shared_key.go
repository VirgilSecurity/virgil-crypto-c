package foundation

import "C"

/*
* Provide interface to compute shared key for 2 asymmetric keys.
*/
type IComputeSharedKey interface {

    IKeyAlg

    /*
    * Compute shared key for 2 asymmetric keys.
    * Note, computed shared key can be used only within symmetric cryptography.
    */
    ComputeSharedKey (publicKey IPublicKey, privateKey IPrivateKey) []byte

    /*
    * Return number of bytes required to hold shared key.
    * Expect Public Key or Private Key.
    */
    SharedKeyLen (key IKey) int32
}

