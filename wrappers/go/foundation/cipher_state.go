package foundation

import "C"

/*
* Enumerates possible sequentail cipher's states.
*/
type CipherState int
const (
    /*
    * Cipher is ready for new encryption / decryption operation.
    */
    CipherStateInitial CipherState = 0
    /*
    * Cipher is configured for encryption.
    */
    CipherStateEncryption CipherState = 1
    /*
    * Cipher is configured for decryption.
    */
    CipherStateDecryption CipherState = 2
)
