package foundation

import "C"

/*
* Provide interface for "message info footer" class serialization.
*/
type IMessageInfoFooterSerializer interface {

    CContext

    /*
    * Return buffer size enough to hold serialized message info footer.
    */
    SerializedFooterLen (messageInfoFooter MessageInfoFooter) int32

    /*
    * Serialize class "message info footer".
    */
    SerializeFooter (messageInfoFooter MessageInfoFooter) []byte

    /*
    * Deserialize class "message info footer".
    */
    DeserializeFooter (data []byte) MessageInfoFooter
}

