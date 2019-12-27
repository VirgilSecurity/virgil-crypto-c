package foundation

import "C"

/*
* Provides generic interface to the Key Encapsulation Mechanism (KEM).
*/
type Kem interface {

    context

    /*
    * Return length in bytes required to hold encapsulated shared key.
    */
    KemSharedKeyLen (key Key) int

    /*
    * Return length in bytes required to hold encapsulated key.
    */
    KemEncapsulatedKeyLen (publicKey PublicKey) int

    /*
    * Generate a shared key and a key encapsulated message.
    */
    KemEncapsulate (publicKey PublicKey) ([]byte, []byte, error)

    /*
    * Decapsulate the shared key.
    */
    KemDecapsulate (encapsulatedKey []byte, privateKey PrivateKey) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

