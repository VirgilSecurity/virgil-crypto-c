package foundation

import "C"

/*
* Provide interface for symmetric key wrapping algorithms (RFC 3394).
*/
type KeyWrap interface {

    context

    /*
    * Return buffer length required to hold a wrapped key for the given plain key length.
    */
    WrappedLen (dataLen uint) uint

    /*
    * Return buffer length required to hold an unwrapped key for the given wrapped key length.
    */
    UnwrappedLen (dataLen uint) uint

    /*
    * Wrap given key data using the Key Encryption Key (KEK).
    */
    Wrap (kek []byte, data []byte) ([]byte, error)

    /*
    * Unwrap given key data using the Key Encryption Key (KEK).
    */
    Unwrap (kek []byte, data []byte) ([]byte, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

