package foundation

import "C"

/*
* Provide algorithm deserialization.
*/
type IAlgInfoDeserializer interface {

    context

    /*
    * Deserialize algorithm from the data.
    */
    Deserialize (data []byte) (IAlgInfo, error)
}

