package ratchet

import "C"

/*
* Represents group message type
*/
type GroupMsgType int
const (
    /*
    * Group info used to create group chat, add or remove participants.
    * Should be distributed only using secure channels.
    */
    GroupMsgTypeGroupInfo GroupMsgType = 1
    /*
    * Regular group ratchet message with cipher text.
    */
    GroupMsgTypeRegular GroupMsgType = 2
)
