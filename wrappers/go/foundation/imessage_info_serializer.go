package foundation

import "C"

/*
* Provide interface for "message info" class serialization.
*/
type IMessageInfoSerializer interface {

    context

    GetPrefixLen () uint32

    /*
    * Return buffer size enough to hold serialized message info.
    */
    SerializedLen (messageInfo *MessageInfo) uint32

    /*
    * Serialize class "message info".
    */
    Serialize (messageInfo *MessageInfo) []byte

    /*
    * Read message info prefix from the given data, and if it is valid,
    * return a length of bytes of the whole message info.
    *
    * Zero returned if length can not be determined from the given data,
    * and this means that there is no message info at the data beginning.
    */
    ReadPrefix (data []byte) uint32

    /*
    * Deserialize class "message info".
    */
    Deserialize (data []byte) (*MessageInfo, error)

    /*
    * Release underlying C context.
    */
    Delete ()
}

