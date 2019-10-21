package foundation

import "C"

/*
* Represents group message type
*/
type GroupMsgType int
const (
    /*
    * Group info type with encryption key.
    * This type of message should be encrypted before transferring.
    */
    GROUP_MSG_TYPE_GROUP_INFO GroupMsgType = 1
    /*
    * Regular group message with encrypted text.
    */
    GROUP_MSG_TYPE_REGULAR GroupMsgType = 2
)
