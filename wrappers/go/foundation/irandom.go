package foundation

import "C"

/*
* Common interface to get random data.
*/
type IRandom interface {

    CContext

    /*
    * Generate random bytes.
    * All RNG implementations must be thread-safe.
    */
    Random (dataLen int32) []byte

    /*
    * Retrieve new seed data from the entropy sources.
    */
    Reseed ()
}
