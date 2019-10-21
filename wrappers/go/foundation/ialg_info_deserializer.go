package foundation

import "C"

/*
* Provide algorithm deserialization.
*/
type IAlgInfoDeserializer interface {

    CContext

    /*
    * Deserialize algorithm from the data.
    */
    Deserialize (data []byte) IAlgInfo
}

