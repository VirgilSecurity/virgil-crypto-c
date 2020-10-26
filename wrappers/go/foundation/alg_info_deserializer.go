package foundation

import "C"

/*
* Provide algorithm deserialization.
*/
type AlgInfoDeserializer interface {

    context

    /*
    * Deserialize algorithm from the data.
    */
    Deserialize (data []byte) (AlgInfo, error)
}

