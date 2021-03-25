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
    GroupMsgTypeGroupInfo GroupMsgType = 1
    /*
    * Regular group message with encrypted text.
    */
    GroupMsgTypeRegular GroupMsgType = 2
)
