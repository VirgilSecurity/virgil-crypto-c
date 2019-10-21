package foundation

import "C"

/*
* Provide interface for "message info" class serialization.
*/
type IMessageInfoSerializer interface {

    CContext

    getPrefixLen () int32

    /*
    * Return buffer size enough to hold serialized message info.
    */
    SerializedLen (messageInfo MessageInfo) int32

    /*
    * Serialize class "message info".
    */
    Serialize (messageInfo MessageInfo) []byte

    /*
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    */
    ReadPrefix (data []byte) int32

    /*
    * Deserialize class "message info".
    */
    Deserialize (data []byte) MessageInfo
}

